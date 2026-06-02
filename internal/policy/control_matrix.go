package policy

import (
	_ "embed"
	"fmt"

	"sigs.k8s.io/yaml"
)

// controlMatrixYAML is the embedded control-traceability matrix (POL-WU-28). It
// is the machine-checkable source mapping every shipped rule to numbered control
// IDs; control_matrix_test.go locks it in sync with the engine's rule set.
//
//go:embed control_matrix.yaml
var controlMatrixYAML []byte

// ControlMatrixEntry maps one shipped rule to its numbered control IDs.
type ControlMatrixEntry struct {
	ID       string   `json:"id"`
	Policy   string   `json:"policy"`
	Severity string   `json:"severity"`
	Controls []string `json:"controls"`
}

// ControlMatrix is the parsed control-traceability matrix.
type ControlMatrix struct {
	BundleVersion string               `json:"bundleVersion"`
	Rules         []ControlMatrixEntry `json:"rules"`
}

// LoadControlMatrix parses the embedded control-traceability matrix.
func LoadControlMatrix() (*ControlMatrix, error) {
	var m ControlMatrix
	if err := yaml.Unmarshal(controlMatrixYAML, &m); err != nil {
		return nil, fmt.Errorf("parse control_matrix.yaml: %w", err)
	}
	return &m, nil
}
