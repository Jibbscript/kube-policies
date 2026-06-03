package e2e

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Jibbscript/kube-policies/test/e2e/framework"
)

// recoveryRTO is the documented Recovery Time Objective for the control plane
// (NIST CP-10(2)). After every admission-webhook AND policy-manager pod is
// force-deleted simultaneously, both Deployments must return to their desired
// available-replica count, the leader Leases must be re-acquired, and the engine
// must reproduce the same admission decisions — all within this bound. 3 minutes
// is generous for a kind cluster (image is already cached locally; the cost is
// scheduling + container start + leader-election lease acquisition + CRD cache
// sync), while still being tight enough to catch a recovery regression.
const recoveryRTO = 3 * time.Minute

// componentLabelSelector selects the pods/Deployment of a kube-policies
// component by its well-known app.kubernetes.io/component label (set by the
// Helm chart on both the admission-webhook and policy-manager Deployments).
func componentLabelSelector(component string) string {
	return "app.kubernetes.io/component=" + component
}

// findDeploymentByComponent returns the single Deployment in operatorNamespace
// carrying the given app.kubernetes.io/component label. The release-name prefix
// of the Deployment name is not hardcoded — it is discovered from the label so
// the spec is independent of the Helm release name.
func findDeploymentByComponent(f *framework.Framework, component string) *appsv1.Deployment {
	deployments, err := f.ClientSet.AppsV1().Deployments(operatorNamespace).List(
		f.Context, metav1.ListOptions{LabelSelector: componentLabelSelector(component)})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		"listing %s Deployments in namespace %s", component, operatorNamespace)
	gomega.Expect(deployments.Items).To(gomega.HaveLen(1),
		"expected exactly one %s Deployment in namespace %s, found %d",
		component, operatorNamespace, len(deployments.Items))
	return &deployments.Items[0]
}

// deploymentFullyAvailable reports whether the Deployment named name in
// operatorNamespace has all desired replicas available and is on its latest
// generation (no rollout still in flight).
func deploymentFullyAvailable(f *framework.Framework, name string) (bool, error) {
	dep, err := f.ClientSet.AppsV1().Deployments(operatorNamespace).Get(
		f.Context, name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	desired := int32(1)
	if dep.Spec.Replicas != nil {
		desired = *dep.Spec.Replicas
	}
	upToDate := dep.Status.ObservedGeneration >= dep.Generation
	return upToDate &&
		dep.Status.AvailableReplicas == desired &&
		dep.Status.UpdatedReplicas == desired &&
		dep.Status.UnavailableReplicas == 0, nil
}

// forceDeletePods deletes every pod matching the component label selector in
// operatorNamespace with GracePeriodSeconds=0 (immediate, ungraceful). Mirrors a
// simultaneous crash of the whole component.
func forceDeletePods(f *framework.Framework, component string) {
	zero := int64(0)
	err := f.ClientSet.CoreV1().Pods(operatorNamespace).DeleteCollection(
		f.Context,
		metav1.DeleteOptions{GracePeriodSeconds: &zero},
		metav1.ListOptions{LabelSelector: componentLabelSelector(component)},
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		"force-deleting %s pods in namespace %s", component, operatorNamespace)
}

// RES-WU-19 (NIST CP-10(2) "Transaction Recovery"): the control plane must
// recover its enforcement posture after a total loss of its running pods. This
// spec, against a live cluster where the operator is deployed HA:
//
//  1. Establishes a known-good decision pre-restart (a privileged pod is denied).
//  2. Force-deletes ALL admission-webhook AND policy-manager pods simultaneously
//     (GracePeriodSeconds=0), selected by component label in operatorNamespace.
//  3. Waits for both Deployments to return to full availability within
//     recoveryRTO, capturing and logging the elapsed recovery time.
//  4. Asserts the leader Leases (coordination.k8s.io/v1) are re-acquired — each
//     has a non-empty holderIdentity post-recovery.
//  5. Asserts the SAME known deny decision is reproduced (engines rebuilt from
//     the CRDs in etcd).
var _ = ginkgo.Describe("State Recovery (RES-WU-19)", func() {
	f := framework.NewFramework("state-recovery")

	ginkgo.It("recovers the enforcement posture after all control-plane pods are force-deleted", func() {
		const denyReason = "Privileged containers are not allowed"

		ginkgo.By("Seeding a Policy that denies privileged containers")
		rules := []map[string]interface{}{
			{
				"name":        "no-privileged-containers",
				"severity":    "HIGH",
				"description": "Privileged containers are not allowed",
				"rego": `
					package kube_policies
					import rego.v1
					default evaluate := {"allowed": true}
					evaluate := {
						"allowed": false,
						"message": "Privileged containers are not allowed",
						"path": sprintf("spec.containers[%d].securityContext.privileged", [i]),
					} if {
						indexes := [j | some j; input.object.spec.containers[j].securityContext.privileged == true]
						count(indexes) > 0
						i := indexes[0]
					}
				`,
			},
		}
		policy := f.CreateSecurityPolicy("state-recovery-policy", rules)
		f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

		ginkgo.By("Establishing the known-good deny decision before restart")
		f.ExpectPodCreationToFail(privilegedPod("pre-restart-privileged"), denyReason)

		ginkgo.By("Discovering the control-plane Deployments by component label")
		webhookDeployment := findDeploymentByComponent(f, "admission-webhook")
		managerDeployment := findDeploymentByComponent(f, "policy-manager")
		ginkgo.By(fmt.Sprintf("admission-webhook Deployment: %s, policy-manager Deployment: %s",
			webhookDeployment.Name, managerDeployment.Name))

		ginkgo.By("Force-deleting ALL admission-webhook AND policy-manager pods simultaneously")
		recoveryStart := time.Now()
		forceDeletePods(f, "admission-webhook")
		forceDeletePods(f, "policy-manager")

		ginkgo.By(fmt.Sprintf("Waiting for both Deployments to return to full availability within %s", recoveryRTO))
		gomega.Eventually(func() (bool, error) {
			webhookReady, err := deploymentFullyAvailable(f, webhookDeployment.Name)
			if err != nil || !webhookReady {
				return false, err
			}
			return deploymentFullyAvailable(f, managerDeployment.Name)
		}, recoveryRTO, 5*time.Second).Should(gomega.BeTrue(),
			"both control-plane Deployments must be fully available within the recovery RTO")
		recoveryElapsed := time.Since(recoveryStart)
		ginkgo.By(fmt.Sprintf("Control plane recovered in %s (RTO bound %s)", recoveryElapsed, recoveryRTO))
		gomega.Expect(recoveryElapsed).To(gomega.BeNumerically("<=", recoveryRTO),
			"recovery elapsed %s exceeded the documented RTO %s", recoveryElapsed, recoveryRTO)

		ginkgo.By("Asserting the leader Leases are re-acquired post-recovery")
		for _, leaseName := range []string{"kube-policies-admission-webhook", "kube-policies-policy-manager"} {
			leaseName := leaseName
			gomega.Eventually(func() (string, error) {
				lease, err := f.ClientSet.CoordinationV1().Leases(operatorNamespace).Get(
					f.Context, leaseName, metav1.GetOptions{})
				if err != nil {
					return "", err
				}
				if lease.Spec.HolderIdentity == nil {
					return "", nil
				}
				return *lease.Spec.HolderIdentity, nil
			}, recoveryRTO, 5*time.Second).ShouldNot(gomega.BeEmpty(),
				"Lease/%s must have a holderIdentity after recovery — a manager must re-acquire leadership", leaseName)
			ginkgo.By("Lease re-acquired: " + leaseName)
		}

		ginkgo.By("Asserting the same deny decision is reproduced after recovery")
		gomega.Eventually(func() error {
			pod := privilegedPod("post-restart-privileged")
			pod.Namespace = f.Namespace
			_, createErr := f.ClientSet.CoreV1().Pods(f.Namespace).Create(
				f.Context, pod, metav1.CreateOptions{})
			// We WANT this to fail with the deny reason. A successful create
			// means the webhook is not yet enforcing again, so keep polling.
			if createErr == nil {
				_ = f.ClientSet.CoreV1().Pods(f.Namespace).Delete(
					f.Context, pod.Name, metav1.DeleteOptions{})
				return errPostureNotRestored
			}
			gomega.Expect(createErr.Error()).To(gomega.ContainSubstring(denyReason))
			return nil
		}, recoveryRTO, 3*time.Second).Should(gomega.Succeed(),
			"after recovery the privileged pod should be denied again with the same reason")

		ginkgo.By("Asserting a compliant pod is still admitted after recovery")
		gomega.Eventually(func() error {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "post-restart-compliant",
					Labels: map[string]string{"test": "e2e"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "compliant-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								Privileged:   &[]bool{false}[0],
								RunAsUser:    &[]int64{1000}[0],
								RunAsNonRoot: &[]bool{true}[0],
							},
						},
					},
				},
			}
			pod.Namespace = f.Namespace
			created, createErr := f.ClientSet.CoreV1().Pods(f.Namespace).Create(
				f.Context, pod, metav1.CreateOptions{})
			if createErr != nil {
				return createErr
			}
			_ = f.ClientSet.CoreV1().Pods(f.Namespace).Delete(
				f.Context, created.Name, metav1.DeleteOptions{})
			return nil
		}, recoveryRTO, 3*time.Second).Should(gomega.Succeed(),
			"after recovery a compliant pod should still be admitted")

		ginkgo.By("Cleaning up the policy")
		f.DeletePolicy(policy.GetName(), policy.GetNamespace())
	})
})
