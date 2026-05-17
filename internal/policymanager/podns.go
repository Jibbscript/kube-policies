package policymanager

import (
	"fmt"
	"os"
	"strings"
)

// ResolvePodNamespace returns the Kubernetes namespace the current pod belongs
// to. It checks the POD_NAMESPACE environment variable first (non-empty wins);
// if that is empty or unset, it falls back to reading saTokenNSPath (the
// standard service-account-mounted namespace file inside a Pod is
// /var/run/secrets/kubernetes.io/serviceaccount/namespace).
//
// The saTokenNSPath parameter is parameterized so that tests can supply a
// temp-file path instead of depending on the in-cluster path.
//
// Returns an error when both sources are unavailable or empty.
func ResolvePodNamespace(saTokenNSPath string) (string, error) {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns, nil
	}
	data, err := os.ReadFile(saTokenNSPath)
	if err != nil {
		return "", fmt.Errorf("namespace not resolvable: env POD_NAMESPACE empty and file %q: %w", saTokenNSPath, err)
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", fmt.Errorf("namespace not resolvable: env POD_NAMESPACE empty and file %q is empty", saTokenNSPath)
	}
	return ns, nil
}
