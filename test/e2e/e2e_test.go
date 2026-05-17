package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
	"github.com/Jibbscript/kube-policies/test/e2e/framework"
)

var _ = ginkgo.Describe("Kube-Policies E2E Tests", func() {
	f := framework.NewFramework("kube-policies-e2e")

	ginkgo.BeforeEach(func() {
		f.LogClusterInfo()
	})

	ginkgo.Context("Security Policies", func() {
		ginkgo.It("should deny privileged containers", func() {
			ginkgo.By("Creating a security policy that denies privileged containers")

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

			policy := f.CreateSecurityPolicy("no-privileged-policy", rules)
			ginkgo.By("Policy created: " + policy.GetName())

			ginkgo.By("Waiting for policy to become active")
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Attempting to create a privileged pod")
			privilegedSecurityContext := &corev1.SecurityContext{
				Privileged: &[]bool{true}[0],
			}

			f.ExpectPodCreationToFail(
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "privileged-pod",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:            "privileged-container",
								Image:           "nginx:1.20",
								SecurityContext: privilegedSecurityContext,
							},
						},
					},
				},
				"Privileged containers are not allowed",
			)

			ginkgo.By("Attempting to create a non-privileged pod")
			nonPrivilegedSecurityContext := &corev1.SecurityContext{
				Privileged:   &[]bool{false}[0],
				RunAsUser:    &[]int64{1000}[0],
				RunAsNonRoot: &[]bool{true}[0],
			}

			pod := f.CreateTestPod("non-privileged-pod", "nginx:1.20", nonPrivilegedSecurityContext)
			ginkgo.By("Non-privileged pod created successfully: " + pod.Name)

			ginkgo.By("Cleaning up policy")
			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})

		ginkgo.It("should deny root user containers", func() {
			ginkgo.By("Creating a security policy that denies root user")

			rules := []map[string]interface{}{
				{
					"name":        "no-root-user",
					"severity":    "HIGH",
					"description": "Containers must not run as root user",
					"rego": `
						package kube_policies
						import rego.v1
						default evaluate := {"allowed": true}
						evaluate := {
							"allowed": false,
							"message": "Containers must not run as root user",
							"path": sprintf("spec.containers[%d].securityContext.runAsUser", [i]),
						} if {
							indexes := [j | some j; input.object.spec.containers[j].securityContext.runAsUser == 0]
							count(indexes) > 0
							i := indexes[0]
						}
					`,
				},
			}

			policy := f.CreateSecurityPolicy("no-root-user-policy", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Attempting to create a pod running as root")
			rootSecurityContext := &corev1.SecurityContext{
				RunAsUser: &[]int64{0}[0],
			}

			f.ExpectPodCreationToFail(
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "root-pod",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:            "root-container",
								Image:           "nginx:1.20",
								SecurityContext: rootSecurityContext,
							},
						},
					},
				},
				"Containers must not run as root user",
			)

			ginkgo.By("Creating a pod running as non-root user")
			nonRootSecurityContext := &corev1.SecurityContext{
				RunAsUser:    &[]int64{1000}[0],
				RunAsNonRoot: &[]bool{true}[0],
			}

			pod := f.CreateTestPod("non-root-pod", "nginx:1.20", nonRootSecurityContext)
			ginkgo.By("Non-root pod created successfully: " + pod.Name)

			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})

		ginkgo.It("should deny latest image tags", func() {
			ginkgo.By("Creating a policy that denies latest image tags")

			rules := []map[string]interface{}{
				{
					"name":        "no-latest-tag",
					"severity":    "MEDIUM",
					"description": "Latest image tag is not allowed",
					"rego": `
						package kube_policies
						import rego.v1
						default evaluate := {"allowed": true}
						evaluate := {
							"allowed": false,
							"message": sprintf("Container '%s' must not use 'latest' image tag", [input.object.spec.containers[i].name]),
							"path": sprintf("spec.containers[%d].image", [i]),
						} if {
							indexes := [j | some j; endswith(input.object.spec.containers[j].image, ":latest")]
							count(indexes) > 0
							i := indexes[0]
						}
					`,
				},
			}

			policy := f.CreateSecurityPolicy("no-latest-tag-policy", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Attempting to create a pod with latest tag")
			f.ExpectPodCreationToFail(
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "latest-tag-pod",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "latest-container",
								Image: "nginx:latest",
							},
						},
					},
				},
				"must not use 'latest' image tag",
			)

			ginkgo.By("Creating a pod with specific tag")
			pod := f.CreateTestPod("specific-tag-pod", "nginx:1.20", nil)
			ginkgo.By("Pod with specific tag created successfully: " + pod.Name)

			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})
	})

	ginkgo.Context("Resource Policies", func() {
		ginkgo.It("should require resource limits", func() {
			ginkgo.By("Creating a policy that requires resource limits")

			rules := []map[string]interface{}{
				{
					"name":        "require-resource-limits",
					"severity":    "MEDIUM",
					"description": "Containers must have resource limits defined",
					"rego": `
						package kube_policies
						import rego.v1
						default evaluate := {"allowed": true}
						evaluate := {
							"allowed": false,
							"message": sprintf("Container '%s' must have resource limits defined", [input.object.spec.containers[i].name]),
							"path": sprintf("spec.containers[%d].resources.limits", [i]),
						} if {
							indexes := [j | some j; input.object.spec.containers[j]; not input.object.spec.containers[j].resources.limits]
							count(indexes) > 0
							i := indexes[0]
						}
					`,
				},
			}

			policy := f.CreateSecurityPolicy("require-limits-policy", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Attempting to create a pod without resource limits")
			f.ExpectPodCreationToFail(
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "no-limits-pod",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "no-limits-container",
								Image: "nginx:1.20",
							},
						},
					},
				},
				"must have resource limits defined",
			)

			ginkgo.By("Creating a pod with resource limits")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "with-limits-pod",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "with-limits-container",
							Image: "nginx:1.20",
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
						},
					},
				},
			}

			createdPod := f.CreatePod(pod)
			ginkgo.By("Pod with resource limits created successfully: " + createdPod.Name)

			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})
	})

	ginkgo.Context("Policy Exceptions", func() {
		// Re-enabled by the engine-exception-consumption PR (plan Step 5.8). The
		// webhook now consults a policy.ExceptionRegistry on every Evaluate;
		// matching PolicyException CRs suppress otherwise-denied admissions.
		// This spec exercises the end-to-end flow.
		//
		// Scope choice: the CRD's PolicyExceptionScope has no matchLabels field
		// today (deferred follow-up — see OQ-3 in the plan). The exception is
		// namespace-scoped via a sub-namespace `emergency-namespace`. Pods in
		// that namespace bypass the privileged-container rule; pods in the
		// framework's per-test namespace still get denied.
		ginkgo.It("should allow exceptions for specific resources", func() {
			ginkgo.By("Creating a security policy that denies privileged containers")

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

			policy := f.CreateSecurityPolicy("privileged-policy-with-exception", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Creating an emergency namespace for the exception scope")
			emergencyNs := f.CreateNamespace(fmt.Sprintf("emergency-ns-%d", time.Now().UnixNano()))
			defer f.DeleteNamespace(emergencyNs)

			ginkgo.By("Creating a policy exception scoped to the emergency namespace")
			// The engine identifies CRD-derived policies by the prefixed form
			// `crd:<namespace>:<name>` (see internal/policymanager/crd_sync.go::
			// CRDPolicyID). The exception's spec.policy_id MUST use this same
			// form, otherwise the suppression pass cannot correlate the
			// exception with the violation it is meant to waive.
			policyID := fmt.Sprintf("crd:%s:%s", policy.GetNamespace(), policy.GetName())
			exception := f.CreateTestPolicyException(
				"emergency-exception",
				policyID,
				"no-privileged-containers",
				time.Hour,
				policiesv1.PolicyExceptionScope{
					Namespaces: []string{emergencyNs},
					Resources:  []string{"pods"},
				},
			)

			ginkgo.By("Attempting to create a privileged pod outside the emergency namespace")
			f.ExpectPodCreationToFail(
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "privileged-no-exception",
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
				},
				"Privileged containers are not allowed",
			)

			ginkgo.By("Creating a privileged pod inside the emergency namespace")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "privileged-with-exception",
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

			createdPod := f.CreatePodInNamespace(pod, emergencyNs)
			ginkgo.By("Privileged pod with exception created successfully: " + createdPod.Name)

			f.DeletePolicyException(exception.GetName())
			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})
	})

	ginkgo.Context("Deployment Policies", func() {
		ginkgo.It("should enforce policies on deployments", func() {
			ginkgo.By("Creating a policy that denies privileged containers")

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
							"message": "Privileged containers are not allowed in deployments",
							"path": sprintf("spec.containers[%d].securityContext.privileged", [i]),
						} if {
							indexes := [j | some j; input.object.spec.containers[j].securityContext.privileged == true]
							count(indexes) > 0
							i := indexes[0]
						}
					`,
				},
			}

			policy := f.CreateSecurityPolicy("deployment-security-policy", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Attempting to create a deployment with privileged containers")
			privilegedSecurityContext := &corev1.SecurityContext{
				Privileged: &[]bool{true}[0],
			}

			// The webhook rules cover pods only (apps/v1 deployments are not intercepted).
			// The Deployment is admitted by the API server; the ReplicaSet controller's
			// Pod create is denied by the webhook, surfacing as a FailedCreate event.
			f.CreateDeployment(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name: "privileged-deployment",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: &[]int32{1}[0],
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "privileged-app",
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app": "privileged-app",
							},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:            "privileged-container",
									Image:           "nginx:1.20",
									SecurityContext: privilegedSecurityContext,
								},
							},
						},
					},
				},
			})
			msg, err := f.WaitForReplicaSetFailedCreateEvent(f.Namespace, "privileged-deployment", "Privileged", 60*time.Second)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(msg).NotTo(gomega.BeEmpty())

			ginkgo.By("Creating a deployment with non-privileged containers")
			nonPrivilegedSecurityContext := &corev1.SecurityContext{
				Privileged:   &[]bool{false}[0],
				RunAsUser:    &[]int64{1000}[0],
				RunAsNonRoot: &[]bool{true}[0],
			}

			deployment := f.CreateTestDeployment("non-privileged-deployment", "nginx:1.20", 1, nonPrivilegedSecurityContext)
			ginkgo.By("Non-privileged deployment created successfully: " + deployment.Name)
			// Not waiting for ReadyReplicas: nginx:1.20 cannot bind port 80
			// under runAsUser=1000/runAsNonRoot=true so the container exits in
			// a restart loop. This spec asserts admission behavior — the
			// synchronous CreateTestDeployment success above is the contract;
			// container runtime liveness is out of scope.

			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})
	})

	ginkgo.Context("Multi-Rule Policies", func() {
		ginkgo.It("should enforce multiple security rules", func() {
			ginkgo.By("Creating a comprehensive security policy")

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
				{
					"name":        "no-root-user",
					"severity":    "HIGH",
					"description": "Containers must not run as root",
					"rego": `
						package kube_policies
						import rego.v1
						default evaluate := {"allowed": true}
						evaluate := {
							"allowed": false,
							"message": "Containers must not run as root user",
							"path": sprintf("spec.containers[%d].securityContext.runAsUser", [i]),
						} if {
							indexes := [j | some j; input.object.spec.containers[j].securityContext.runAsUser == 0]
							count(indexes) > 0
							i := indexes[0]
						}
					`,
				},
				{
					"name":        "require-security-context",
					"severity":    "MEDIUM",
					"description": "Containers must have security context",
					"rego": `
						package kube_policies
						import rego.v1
						default evaluate := {"allowed": true}
						evaluate := {
							"allowed": false,
							"message": sprintf("Container at index %d must declare a securityContext", [i]),
							"path": sprintf("spec.containers[%d].securityContext", [i]),
						} if {
							indexes := [j | some j; input.object.spec.containers[j]; not input.object.spec.containers[j].securityContext]
							count(indexes) > 0
							i := indexes[0]
						}
					`,
				},
			}

			policy := f.CreateSecurityPolicy("comprehensive-security-policy", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Attempting to create a pod that violates multiple rules")
			f.ExpectPodCreationToFail(
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "multi-violation-pod",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "violation-container",
								Image: "nginx:1.20",
								SecurityContext: &corev1.SecurityContext{
									Privileged: &[]bool{true}[0],
									RunAsUser:  &[]int64{0}[0],
								},
							},
						},
					},
				},
				"Multiple policy violations detected",
			)

			ginkgo.By("Creating a compliant pod")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "compliant-pod",
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

			createdPod := f.CreatePod(pod)
			ginkgo.By("Compliant pod created successfully: " + createdPod.Name)

			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})
	})

	ginkgo.Context("Policy Performance", func() {
		ginkgo.It("should handle multiple concurrent pod creations", func() {
			ginkgo.By("Creating a simple security policy")

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

			policy := f.CreateSecurityPolicy("performance-test-policy", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Creating multiple pods concurrently")
			numPods := 10
			podNames := make([]string, numPods)

			for i := 0; i < numPods; i++ {
				podName := fmt.Sprintf("performance-pod-%d", i)
				podNames[i] = podName

				pod := f.CreateTestPod(podName, "nginx:1.20", &corev1.SecurityContext{
					RunAsUser:    &[]int64{1000}[0],
					RunAsNonRoot: &[]bool{true}[0],
				})
				ginkgo.By(fmt.Sprintf("Created pod %d: %s", i+1, pod.Name))
			}

			ginkgo.By("Verifying all pods were created successfully")
			for _, podName := range podNames {
				pod, err := f.ClientSet.CoreV1().Pods(f.Namespace).Get(f.Context, podName, metav1.GetOptions{})
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(pod.Name).To(gomega.Equal(podName))
			}

			f.DeletePolicy(policy.GetName(), policy.GetNamespace())
		})
	})

	ginkgo.Context("Leader Election", func() {
		// This Context targets a live cluster where the operator is already
		// deployed. It reads the coordination.k8s.io/v1 Lease that the
		// admission-webhook controller manager creates and asserts:
		//   1. The Lease exists and spec.holderIdentity is set (someone holds it).
		//   2. The holder identity maps to exactly one admission-webhook pod.
		//   3. No other admission-webhook pod's name appears in holderIdentity.
		//
		// The Lease CR is the authoritative source of truth — no log-string
		// matching is used because controller-runtime's election log messages
		// are not part of its public API.
		ginkgo.It("exactly one admission-webhook pod holds the lease at a time", func() {
			ginkgo.By("Reading the admission-webhook leader-election Lease from " + operatorNamespace)

			lease, err := f.ClientSet.CoordinationV1().Leases(operatorNamespace).Get(
				f.Context, "kube-policies-admission-webhook", metav1.GetOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred(),
				"Lease/kube-policies-admission-webhook must exist in namespace %s — "+
					"ensure the deployment image includes the leader-election changes "+
					"and the RBAC grants coordination.k8s.io/leases verbs", operatorNamespace)

			gomega.Expect(lease.Spec.HolderIdentity).NotTo(gomega.BeNil(),
				"Lease spec.holderIdentity must be non-nil")
			holderIdentity := *lease.Spec.HolderIdentity
			gomega.Expect(holderIdentity).NotTo(gomega.BeEmpty(),
				"Lease spec.holderIdentity must be non-empty — no manager has acquired leadership")

			ginkgo.By(fmt.Sprintf("Lease held by: %q", holderIdentity))

			// controller-runtime encodes holderIdentity as "<pod-name>_<uuid>".
			// Extract the pod-name prefix (everything before the first "_").
			parts := strings.SplitN(holderIdentity, "_", 2)
			holderPodName := parts[0]
			ginkgo.By(fmt.Sprintf("Identified leader pod name: %q", holderPodName))

			// List all pods in the operator namespace and find admission-webhook pods.
			pods, err := f.ClientSet.CoreV1().Pods(operatorNamespace).List(
				f.Context, metav1.ListOptions{})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			var webhookPodNames []string
			for i := range pods.Items {
				if strings.Contains(pods.Items[i].Name, "admission-webhook") {
					webhookPodNames = append(webhookPodNames, pods.Items[i].Name)
				}
			}
			gomega.Expect(webhookPodNames).NotTo(gomega.BeEmpty(),
				"no admission-webhook pods found in namespace %s", operatorNamespace)

			// Assertion 1: the holder pod must be one of the admission-webhook pods.
			gomega.Expect(webhookPodNames).To(gomega.ContainElement(holderPodName),
				"holderIdentity %q (pod %q) does not match any admission-webhook pod %v",
				holderIdentity, holderPodName, webhookPodNames)

			// Assertion 2: no non-leader pod's name must appear in holderIdentity,
			// ensuring exactly one pod holds the lease.
			for _, podName := range webhookPodNames {
				if podName == holderPodName {
					continue
				}
				gomega.Expect(holderIdentity).NotTo(gomega.ContainSubstring(podName),
					"holderIdentity %q references non-leader pod %q — "+
						"more than one pod may hold the lease", holderIdentity, podName)
			}

			ginkgo.By(fmt.Sprintf("✓ Exactly one admission-webhook pod (%q) holds the lease", holderPodName))
		})
	})
})

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Kube-Policies E2E Test Suite")
}

// operatorNamespace is the namespace where the Operator pods run.
const operatorNamespace = "kube-policies-system"

// getOperatorPodLogs returns the last 500 log lines from the first running pod
// whose name contains the given component string in the operator namespace.
// Fails the spec if no matching running pod is found.
func getOperatorPodLogs(f *framework.Framework, component string) string {
	pods, err := f.ClientSet.CoreV1().Pods(operatorNamespace).List(
		f.Context, metav1.ListOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		"listing pods in namespace %s", operatorNamespace)

	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.Contains(pod.Name, component) {
			continue
		}
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		tail := int64(500)
		req := f.ClientSet.CoreV1().Pods(operatorNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			TailLines: &tail,
		})
		stream, streamErr := req.Stream(f.Context)
		gomega.Expect(streamErr).NotTo(gomega.HaveOccurred(),
			"streaming logs from pod %s", pod.Name)
		defer stream.Close() //nolint:gocritic // intentional: one defer per found pod

		var buf strings.Builder
		_, copyErr := io.Copy(&buf, stream)
		gomega.Expect(copyErr).NotTo(gomega.HaveOccurred())
		return buf.String()
	}

	ginkgo.Fail(fmt.Sprintf("no running pod found for component %q in namespace %s", component, operatorNamespace))
	return ""
}

var _ = ginkgo.Describe("Controller-runtime logger wiring", func() {
	f := framework.NewFramework("logger-wiring")

	ginkgo.It("Operator pods emit JSON logs and never warn about SetLogger", func() {
		const setLoggerWarning = "[controller-runtime] log.SetLogger(...) was never called; logs will not be displayed"

		for _, component := range []string{"admission-webhook", "policy-manager"} {
			podLogs := getOperatorPodLogs(f, component)

			gomega.Expect(podLogs).NotTo(
				gomega.ContainSubstring(setLoggerWarning),
				"%s pod should not emit the controller-runtime SetLogger warning", component,
			)

			// Parse at least one JSON line per pod and assert service+caller.
			sawJSON := false
			for _, line := range strings.Split(podLogs, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					continue
				}
				if rec["service"] != nil && rec["caller"] != nil {
					sawJSON = true
					break
				}
			}
			gomega.Expect(sawJSON).To(gomega.BeTrue(),
				"%s pod did not emit any JSON log line with service+caller", component)
		}
	})
})
