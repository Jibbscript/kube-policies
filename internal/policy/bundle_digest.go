package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// bundleRuleDigest is the canonical, order-independent description of one shipped
// rule used to compute the signed bundle digest (POL-WU-27).
type bundleRuleDigest struct {
	Policy      string   `json:"policy"`
	Rule        string   `json:"rule"`
	Version     string   `json:"version"`
	TargetKinds []string `json:"targetKinds"`
	Rego        string   `json:"rego"`
}

// BundleManifest is the canonical description of the shipped policy library: the
// bundle version, the shared library module sources, and every bundled rule, in
// a deterministic order. A release computes this, signs its SHA-256 digest with
// cosign, and emits SLSA provenance so deployers can verify the policy pack's
// integrity and origin (POL-WU-27). It is reproducible from the source tree, so
// CI can re-derive the digest and verify the signature.
type BundleManifest struct {
	BundleVersion string             `json:"bundleVersion"`
	Library       map[string]string  `json:"library"`
	Rules         []bundleRuleDigest `json:"rules"`
}

// ComputeBundleManifest builds the canonical manifest over every shipped bundled
// rule (enabled or not) and the shared library modules.
func ComputeBundleManifest() (*BundleManifest, error) {
	eng, err := NewEngine(&config.PolicyConfig{}, zap.NewNop())
	if err != nil {
		return nil, fmt.Errorf("build bundle manifest: %w", err)
	}

	m := &BundleManifest{
		BundleVersion: PolicyBundleVersion,
		Library:       LibrarySources(),
	}
	for _, p := range eng.ListPolicies() {
		for _, r := range p.Rules {
			tk := append([]string(nil), r.TargetKinds...)
			sort.Strings(tk)
			m.Rules = append(m.Rules, bundleRuleDigest{
				Policy:      p.ID,
				Rule:        r.ID,
				Version:     p.Version,
				TargetKinds: tk,
				Rego:        r.Rego,
			})
		}
	}
	sort.Slice(m.Rules, func(i, j int) bool {
		if m.Rules[i].Policy != m.Rules[j].Policy {
			return m.Rules[i].Policy < m.Rules[j].Policy
		}
		return m.Rules[i].Rule < m.Rules[j].Rule
	})
	return m, nil
}

// BundleManifestJSON returns the manifest as canonical (sorted-key) JSON bytes.
func BundleManifestJSON() ([]byte, error) {
	m, err := ComputeBundleManifest()
	if err != nil {
		return nil, err
	}
	// encoding/json marshals map keys in sorted order, so this is canonical.
	return json.Marshal(m)
}

// BundleDigest returns the SHA-256 hex digest of the canonical bundle manifest.
// Any change to a shipped rule, the shared library, or the bundle version
// changes the digest.
func BundleDigest() (string, error) {
	b, err := BundleManifestJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
