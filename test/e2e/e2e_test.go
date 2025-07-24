package e2e

import (
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/kube-policies/test/e2e/framework"
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
						package kube_policies.security
						deny[msg] {
							input.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
						deny[msg] {
							input.spec.securityContext.privileged == true
							msg := "Privileged containers are not allowed"
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
						package kube_policies.security
						deny[msg] {
							input.spec.containers[_].securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
						}
						deny[msg] {
							input.spec.securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
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
						package kube_policies.security
						import future.keywords.contains
						deny[msg] {
							container := input.spec.containers[_]
							endswith(container.image, ":latest")
							msg := sprintf("Container '%s' must not use 'latest' image tag", [container.name])
						}
						deny[msg] {
							container := input.spec.containers[_]
							not contains(container.image, ":")
							msg := sprintf("Container '%s' must specify explicit image tag", [container.name])
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
						package kube_policies.resources
						deny[msg] {
							container := input.spec.containers[_]
							not container.resources.limits
							msg := sprintf("Container '%s' must have resource limits defined", [container.name])
						}
						deny[msg] {
							container := input.spec.containers[_]
							not container.resources.limits.cpu
							msg := sprintf("Container '%s' must have CPU limits defined", [container.name])
						}
						deny[msg] {
							container := input.spec.containers[_]
							not container.resources.limits.memory
							msg := sprintf("Container '%s' must have memory limits defined", [container.name])
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
		ginkgo.It("should allow exceptions for specific resources", func() {
			ginkgo.By("Creating a security policy that denies privileged containers")
			
			rules := []map[string]interface{}{
				{
					"name":        "no-privileged-containers",
					"severity":    "HIGH",
					"description": "Privileged containers are not allowed",
					"rego": `
						package kube_policies.security
						deny[msg] {
							input.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
					`,
				},
			}

			policy := f.CreateSecurityPolicy("privileged-policy-with-exception", rules)
			f.WaitForPolicyActive(policy.GetName(), policy.GetNamespace(), 30*time.Second)

			ginkgo.By("Creating a policy exception for emergency deployments")
			exception := f.CreateTestPolicyException(
				"emergency-exception",
				policy.GetName(),
				[]string{"no-privileged-containers"},
				map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"emergency": "true",
					},
				},
			)

			ginkgo.By("Attempting to create a privileged pod without exception label")
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

			ginkgo.By("Creating a privileged pod with exception label")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "privileged-with-exception",
					Labels: map[string]string{
						"emergency": "true",
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

			createdPod := f.CreatePod(pod)
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
						package kube_policies.security
						deny[msg] {
							input.spec.template.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed in deployments"
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

			f.ExpectDeploymentCreationToFail(
				&appsv1.Deployment{
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
				},
				"Privileged containers are not allowed",
			)

			ginkgo.By("Creating a deployment with non-privileged containers")
			nonPrivilegedSecurityContext := &corev1.SecurityContext{
				Privileged:   &[]bool{false}[0],
				RunAsUser:    &[]int64{1000}[0],
				RunAsNonRoot: &[]bool{true}[0],
			}

			deployment := f.CreateTestDeployment("non-privileged-deployment", "nginx:1.20", 1, nonPrivilegedSecurityContext)
			ginkgo.By("Non-privileged deployment created successfully: " + deployment.Name)

			f.WaitForDeploymentReady(deployment.Name, 60*time.Second)

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
						package kube_policies.security
						deny[msg] {
							input.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
					`,
				},
				{
					"name":        "no-root-user",
					"severity":    "HIGH",
					"description": "Containers must not run as root",
					"rego": `
						package kube_policies.security
						deny[msg] {
							input.spec.containers[_].securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
						}
					`,
				},
				{
					"name":        "require-security-context",
					"severity":    "MEDIUM",
					"description": "Containers must have security context",
					"rego": `
						package kube_policies.security
						deny[msg] {
							container := input.spec.containers[_]
							not container.securityContext
							msg := sprintf("Container '%s' must have security context defined", [container.name])
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
				"Privileged containers are not allowed",
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
						package kube_policies.security
						deny[msg] {
							input.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed"
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
})

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Kube-Policies E2E Test Suite")
}

