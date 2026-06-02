package e2e

import (
	"errors"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
	"github.com/Jibbscript/kube-policies/test/e2e/framework"
)

// errPostureNotRestored is a sentinel returned inside Eventually polling loops
// when an admission decision has not yet returned to its expected state. Using a
// sentinel keeps the loop body free of inline error construction. Shared with
// state_recovery_test.go (same package).
var errPostureNotRestored = errors.New("admission posture not yet restored")

// privilegedPod builds an unscheduled Pod with a privileged container — the
// canonical input the `no-privileged-containers` rule denies. The namespace is
// left empty; callers set it (framework helpers default it to the per-test
// namespace). Shared with state_recovery_test.go (same package).
func privilegedPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"test": "e2e",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "privileged-container",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &[]bool{true}[0],
					},
				},
			},
		},
	}
}

// stripForRestore removes the server-populated, non-re-appliable fields from a
// CR captured for backup so the object can be re-Created verbatim. It clears
// resourceVersion/uid/managedFields/creationTimestamp/generation and drops the
// status subresource (it is reconstructed by the controller on restore).
func stripForRestore(obj *unstructured.Unstructured) {
	obj.SetResourceVersion("")
	obj.SetUID("")
	obj.SetManagedFields(nil)
	obj.SetCreationTimestamp(metav1.Time{})
	obj.SetGeneration(0)
	unstructured.RemoveNestedField(obj.Object, "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(obj.Object, "status")
}

// RES-WU-14 (NIST CP-9 "Information System Backup" / CP-10(2) "Transaction
// Recovery"): the policy posture lives entirely in CRDs (Policies +
// PolicyExceptions) — etcd is the system of record (docs/state-model.md). This
// spec exercises the operator backup/restore workflow end-to-end against a live
// cluster:
//
//  1. Seed a Policy + a PolicyException and wait for the Policy to go Active.
//  2. "Back up" by exporting the live CRs via the dynamic client and stripping
//     the server-populated fields (resourceVersion/uid/managedFields/
//     creationTimestamp/generation + the whole status block) so the captured
//     objects are re-appliable verbatim.
//  3. Delete the CRs and verify the posture actually changed (the deny stops
//     firing once the Policy is gone).
//  4. "Restore" by recreating the CRs from the captured backup objects, then
//     wait for the Policy to go Active again.
//  5. Assert equivalence: the restored Policy spec is deep-equal to the seeded
//     spec AND the known admission decision is reproduced (the deny fires again).
//
// Any failure to export, delete, or restore a seeded resource fails the spec.
var _ = ginkgo.Describe("Backup and Restore (RES-WU-14)", func() {
	f := framework.NewFramework("backup-restore")

	// GVRs for the policy CRDs. group policies.kube-policies.io / v1.
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}
	exceptionGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policyexceptions",
	}

	ginkgo.It("restores the policy posture from a CR backup", func() {
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

		seededPolicy := f.CreateSecurityPolicy("backup-restore-policy", rules)
		policyName := seededPolicy.GetName()
		policyNamespace := seededPolicy.GetNamespace()
		ginkgo.By("Policy created: " + policyName)

		f.WaitForPolicyActive(policyName, policyNamespace, 30*time.Second)

		ginkgo.By("Seeding a PolicyException scoped to the test namespace")
		policyID := "crd:" + policyNamespace + ":" + policyName
		seededException := f.CreateTestPolicyException(
			"backup-restore-exception",
			policyID,
			"no-privileged-containers",
			time.Hour,
			policiesv1.PolicyExceptionScope{
				Namespaces: []string{"backup-restore-never-matches"},
				Resources:  []string{"pods"},
			},
		)
		exceptionName := seededException.GetName()
		exceptionNamespace := seededException.GetNamespace()
		ginkgo.By("PolicyException created: " + exceptionName)

		ginkgo.By("Establishing the known-good deny decision before backup")
		f.ExpectPodCreationToFail(privilegedPod("pre-backup-privileged"), denyReason)

		ginkgo.By("Backing up: exporting the live CRs and stripping server-populated fields")
		policyBackup, err := f.DynamicClient.Resource(policyGVR).Namespace(policyNamespace).Get(
			f.Context, policyName, metav1.GetOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to export Policy for backup")
		stripForRestore(policyBackup)
		// Capture the seeded spec so we can assert deep-equality after restore.
		seededSpec, found, err := unstructured.NestedMap(policyBackup.Object, "spec")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeTrue(), "exported Policy backup must carry a spec")

		exceptionBackup, err := f.DynamicClient.Resource(exceptionGVR).Namespace(exceptionNamespace).Get(
			f.Context, exceptionName, metav1.GetOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to export PolicyException for backup")
		stripForRestore(exceptionBackup)

		ginkgo.By("Deleting the CRs (simulating data loss)")
		err = f.DynamicClient.Resource(policyGVR).Namespace(policyNamespace).Delete(
			f.Context, policyName, metav1.DeleteOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to delete Policy")
		err = f.DynamicClient.Resource(exceptionGVR).Namespace(exceptionNamespace).Delete(
			f.Context, exceptionName, metav1.DeleteOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to delete PolicyException")

		ginkgo.By("Verifying the CRs are gone")
		gomega.Eventually(func() bool {
			_, getErr := f.DynamicClient.Resource(policyGVR).Namespace(policyNamespace).Get(
				f.Context, policyName, metav1.GetOptions{})
			return apierrors.IsNotFound(getErr)
		}, 30*time.Second, 2*time.Second).Should(gomega.BeTrue(), "Policy was not deleted")
		gomega.Eventually(func() bool {
			_, getErr := f.DynamicClient.Resource(exceptionGVR).Namespace(exceptionNamespace).Get(
				f.Context, exceptionName, metav1.GetOptions{})
			return apierrors.IsNotFound(getErr)
		}, 30*time.Second, 2*time.Second).Should(gomega.BeTrue(), "PolicyException was not deleted")

		ginkgo.By("Verifying the posture changed: the deny no longer fires")
		gomega.Eventually(func() error {
			pod := privilegedPod("post-delete-privileged")
			pod.Namespace = f.Namespace
			created, createErr := f.ClientSet.CoreV1().Pods(f.Namespace).Create(
				f.Context, pod, metav1.CreateOptions{})
			if createErr != nil {
				// Still being denied; the engine has not yet dropped the policy.
				return createErr
			}
			// Posture confirmed open — clean up the pod we just admitted.
			_ = f.ClientSet.CoreV1().Pods(f.Namespace).Delete(
				f.Context, created.Name, metav1.DeleteOptions{})
			return nil
		}, 60*time.Second, 3*time.Second).Should(gomega.Succeed(),
			"after deleting the Policy the privileged pod should be admitted")

		ginkgo.By("Restoring: recreating the CRs from the captured backup objects")
		restoredPolicy, err := f.DynamicClient.Resource(policyGVR).Namespace(policyNamespace).Create(
			f.Context, policyBackup, metav1.CreateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to restore Policy from backup")
		_, err = f.DynamicClient.Resource(exceptionGVR).Namespace(exceptionNamespace).Create(
			f.Context, exceptionBackup, metav1.CreateOptions{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to restore PolicyException from backup")

		ginkgo.By("Waiting for the restored Policy to go Active")
		f.WaitForPolicyActive(policyName, policyNamespace, 30*time.Second)

		ginkgo.By("Asserting the restored Policy spec matches the seeded spec")
		restoredSpec, found, err := unstructured.NestedMap(restoredPolicy.Object, "spec")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(found).To(gomega.BeTrue(), "restored Policy must carry a spec")
		gomega.Expect(restoredSpec).To(gomega.Equal(seededSpec),
			"restored Policy spec must be identical to the seeded spec")

		ginkgo.By("Asserting the known admission decision is reproduced after restore")
		gomega.Eventually(func() error {
			pod := privilegedPod("post-restore-privileged")
			pod.Namespace = f.Namespace
			_, createErr := f.ClientSet.CoreV1().Pods(f.Namespace).Create(
				f.Context, pod, metav1.CreateOptions{})
			// We WANT this to fail with the deny reason; success means the
			// posture has not been restored yet, so keep polling.
			if createErr == nil {
				_ = f.ClientSet.CoreV1().Pods(f.Namespace).Delete(
					f.Context, pod.Name, metav1.DeleteOptions{})
				return errPostureNotRestored
			}
			gomega.Expect(createErr.Error()).To(gomega.ContainSubstring(denyReason))
			return nil
		}, 60*time.Second, 3*time.Second).Should(gomega.Succeed(),
			"after restore the privileged pod should be denied again")

		ginkgo.By("Cleaning up the restored CRs")
		f.DeletePolicy(policyName, policyNamespace)
		f.DeletePolicyException(exceptionName)
	})
})
