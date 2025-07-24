package framework

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Framework provides utilities for E2E testing
type Framework struct {
	BaseName      string
	Namespace     string
	ClientSet     kubernetes.Interface
	DynamicClient dynamic.Interface
	Config        *rest.Config
	Context       context.Context
}

// NewFramework creates a new E2E testing framework
func NewFramework(baseName string) *Framework {
	f := &Framework{
		BaseName: baseName,
		Context:  context.Background(),
	}

	ginkgo.BeforeEach(f.BeforeEach)
	ginkgo.AfterEach(f.AfterEach)

	return f
}

// BeforeEach sets up the test environment before each test
func (f *Framework) BeforeEach() {
	ginkgo.By("Setting up test environment")

	// Create unique namespace for this test
	f.Namespace = fmt.Sprintf("e2e-%s-%d", f.BaseName, time.Now().Unix())

	// Initialize Kubernetes clients
	var err error
	f.Config, err = f.getKubeConfig()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	f.ClientSet, err = kubernetes.NewForConfig(f.Config)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	f.DynamicClient, err = dynamic.NewForConfig(f.Config)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	// Create test namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: f.Namespace,
			Labels: map[string]string{
				"test-framework": "kube-policies-e2e",
				"test-run":       f.BaseName,
			},
		},
	}

	_, err = f.ClientSet.CoreV1().Namespaces().Create(f.Context, namespace, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	ginkgo.By(fmt.Sprintf("Created test namespace: %s", f.Namespace))
}

// AfterEach cleans up the test environment after each test
func (f *Framework) AfterEach() {
	ginkgo.By("Cleaning up test environment")

	if f.Namespace != "" {
		// Delete test namespace
		err := f.ClientSet.CoreV1().Namespaces().Delete(f.Context, f.Namespace, metav1.DeleteOptions{})
		if err != nil {
			ginkgo.By(fmt.Sprintf("Failed to delete namespace %s: %v", f.Namespace, err))
		} else {
			ginkgo.By(fmt.Sprintf("Deleted test namespace: %s", f.Namespace))
		}
	}
}

// getKubeConfig returns the Kubernetes configuration
func (f *Framework) getKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	// Fall back to kubeconfig file
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// CreatePod creates a pod in the test namespace
func (f *Framework) CreatePod(pod *corev1.Pod) *corev1.Pod {
	pod.Namespace = f.Namespace
	createdPod, err := f.ClientSet.CoreV1().Pods(f.Namespace).Create(f.Context, pod, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return createdPod
}

// CreateDeployment creates a deployment in the test namespace
func (f *Framework) CreateDeployment(deployment *appsv1.Deployment) *appsv1.Deployment {
	deployment.Namespace = f.Namespace
	createdDeployment, err := f.ClientSet.AppsV1().Deployments(f.Namespace).Create(f.Context, deployment, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return createdDeployment
}

// CreatePolicy creates a policy using the dynamic client
func (f *Framework) CreatePolicy(policy *unstructured.Unstructured) *unstructured.Unstructured {
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	// Set namespace if not specified
	if policy.GetNamespace() == "" {
		policy.SetNamespace("kube-policies-system")
	}

	createdPolicy, err := f.DynamicClient.Resource(policyGVR).Namespace(policy.GetNamespace()).Create(
		f.Context, policy, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return createdPolicy
}

// CreatePolicyException creates a policy exception using the dynamic client
func (f *Framework) CreatePolicyException(exception *unstructured.Unstructured) *unstructured.Unstructured {
	exceptionGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policyexceptions",
	}

	exception.SetNamespace(f.Namespace)
	createdException, err := f.DynamicClient.Resource(exceptionGVR).Namespace(f.Namespace).Create(
		f.Context, exception, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return createdException
}

// WaitForPodRunning waits for a pod to be in running state
func (f *Framework) WaitForPodRunning(podName string, timeout time.Duration) {
	err := wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		pod, err := f.ClientSet.CoreV1().Pods(f.Namespace).Get(f.Context, podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

// WaitForDeploymentReady waits for a deployment to be ready
func (f *Framework) WaitForDeploymentReady(deploymentName string, timeout time.Duration) {
	err := wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		deployment, err := f.ClientSet.AppsV1().Deployments(f.Namespace).Get(f.Context, deploymentName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return deployment.Status.ReadyReplicas == *deployment.Spec.Replicas, nil
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

// WaitForPolicyActive waits for a policy to be active
func (f *Framework) WaitForPolicyActive(policyName, policyNamespace string, timeout time.Duration) {
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	err := wait.PollImmediate(2*time.Second, timeout, func() (bool, error) {
		policy, err := f.DynamicClient.Resource(policyGVR).Namespace(policyNamespace).Get(
			f.Context, policyName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		status, found, err := unstructured.NestedMap(policy.Object, "status")
		if err != nil || !found {
			return false, nil
		}

		phase, found, err := unstructured.NestedString(status, "phase")
		if err != nil || !found {
			return false, nil
		}

		return phase == "Active", nil
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

// ExpectPodCreationToFail expects pod creation to fail due to policy violation
func (f *Framework) ExpectPodCreationToFail(pod *corev1.Pod, expectedReason string) {
	pod.Namespace = f.Namespace
	_, err := f.ClientSet.CoreV1().Pods(f.Namespace).Create(f.Context, pod, metav1.CreateOptions{})
	gomega.Expect(err).To(gomega.HaveOccurred())
	gomega.Expect(err.Error()).To(gomega.ContainSubstring(expectedReason))
}

// ExpectDeploymentCreationToFail expects deployment creation to fail due to policy violation
func (f *Framework) ExpectDeploymentCreationToFail(deployment *appsv1.Deployment, expectedReason string) {
	deployment.Namespace = f.Namespace
	_, err := f.ClientSet.AppsV1().Deployments(f.Namespace).Create(f.Context, deployment, metav1.CreateOptions{})
	gomega.Expect(err).To(gomega.HaveOccurred())
	gomega.Expect(err.Error()).To(gomega.ContainSubstring(expectedReason))
}

// GetPodEvents returns events for a specific pod
func (f *Framework) GetPodEvents(podName string) []corev1.Event {
	events, err := f.ClientSet.CoreV1().Events(f.Namespace).List(f.Context, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=Pod", podName),
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return events.Items
}

// GetPolicyViolationEvents returns policy violation events
func (f *Framework) GetPolicyViolationEvents() []corev1.Event {
	events, err := f.ClientSet.CoreV1().Events(f.Namespace).List(f.Context, metav1.ListOptions{
		FieldSelector: "reason=PolicyViolation",
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return events.Items
}

// DeletePolicy deletes a policy
func (f *Framework) DeletePolicy(policyName, policyNamespace string) {
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	err := f.DynamicClient.Resource(policyGVR).Namespace(policyNamespace).Delete(
		f.Context, policyName, metav1.DeleteOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

// DeletePolicyException deletes a policy exception
func (f *Framework) DeletePolicyException(exceptionName string) {
	exceptionGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policyexceptions",
	}

	err := f.DynamicClient.Resource(exceptionGVR).Namespace(f.Namespace).Delete(
		f.Context, exceptionName, metav1.DeleteOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

// CreateTestPod creates a standard test pod
func (f *Framework) CreateTestPod(name string, image string, securityContext *corev1.SecurityContext) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app":  name,
				"test": "e2e",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            name,
					Image:           image,
					SecurityContext: securityContext,
				},
			},
		},
	}

	return f.CreatePod(pod)
}

// CreateTestDeployment creates a standard test deployment
func (f *Framework) CreateTestDeployment(name string, image string, replicas int32, securityContext *corev1.SecurityContext) *appsv1.Deployment {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app":  name,
				"test": "e2e",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            name,
							Image:           image,
							SecurityContext: securityContext,
						},
					},
				},
			},
		},
	}

	return f.CreateDeployment(deployment)
}

// CreateSecurityPolicy creates a standard security policy
func (f *Framework) CreateSecurityPolicy(name string, rules []map[string]interface{}) *unstructured.Unstructured {
	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "policies.kube-policies.io/v1",
			"kind":       "Policy",
			"metadata": map[string]interface{}{
				"name": name,
				"labels": map[string]interface{}{
					"test": "e2e",
				},
			},
			"spec": map[string]interface{}{
				"description": fmt.Sprintf("E2E test policy: %s", name),
				"enabled":     true,
				"enforcement": true,
				"match": []interface{}{
					map[string]interface{}{
						"apiGroups":   []interface{}{""},
						"apiVersions": []interface{}{"v1"},
						"resources":   []interface{}{"pods"},
					},
					map[string]interface{}{
						"apiGroups":   []interface{}{"apps"},
						"apiVersions": []interface{}{"v1"},
						"resources":   []interface{}{"deployments"},
					},
				},
				"rules": rules,
			},
		},
	}

	return f.CreatePolicy(policy)
}

// CreateTestPolicyException creates a standard policy exception
func (f *Framework) CreateTestPolicyException(name, policyName string, rules []string, selector map[string]interface{}) *unstructured.Unstructured {
	exception := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "policies.kube-policies.io/v1",
			"kind":       "PolicyException",
			"metadata": map[string]interface{}{
				"name": name,
				"labels": map[string]interface{}{
					"test": "e2e",
				},
			},
			"spec": map[string]interface{}{
				"description":   fmt.Sprintf("E2E test exception: %s", name),
				"policy":        policyName,
				"rules":         rules,
				"duration":      "1h",
				"justification": "E2E testing exception",
				"selector":      selector,
			},
		},
	}

	return f.CreatePolicyException(exception)
}

// GetClusterInfo returns information about the cluster
func (f *Framework) GetClusterInfo() map[string]string {
	version, err := f.ClientSet.Discovery().ServerVersion()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	nodes, err := f.ClientSet.CoreV1().Nodes().List(f.Context, metav1.ListOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	info := map[string]string{
		"kubernetes_version": version.String(),
		"node_count":         fmt.Sprintf("%d", len(nodes.Items)),
	}

	if len(nodes.Items) > 0 {
		info["node_os"] = nodes.Items[0].Status.NodeInfo.OperatingSystem
		info["node_arch"] = nodes.Items[0].Status.NodeInfo.Architecture
		info["container_runtime"] = nodes.Items[0].Status.NodeInfo.ContainerRuntimeVersion
	}

	return info
}

// LogClusterInfo logs cluster information
func (f *Framework) LogClusterInfo() {
	info := f.GetClusterInfo()
	ginkgo.By("Cluster Information:")
	for key, value := range info {
		ginkgo.By(fmt.Sprintf("  %s: %s", key, value))
	}
}

