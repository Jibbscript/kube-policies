// Command policybundle emits the canonical policy-bundle manifest and digest
// (POL-WU-27) for release-time signing and CI verification.
//
//	policybundle manifest   # canonical manifest JSON to stdout
//	policybundle digest     # SHA-256 hex digest of the manifest to stdout
//
// A release signs the digest (cosign) and attaches SLSA provenance; CI
// re-derives the digest from source and verifies the signature. See
// docs/policy-bundle-verification.md.
package main

import (
	"fmt"
	"os"

	"github.com/Jibbscript/kube-policies/internal/policy"
)

func main() {
	mode := "manifest"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	switch mode {
	case "manifest":
		b, err := policy.BundleManifestJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, "policybundle:", err)
			os.Exit(1)
		}
		// Check the write: this output is piped into sha256/cosign at release
		// time, so a silent short write would yield a hard-to-diagnose digest
		// mismatch.
		if _, err := os.Stdout.Write(append(b, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, "policybundle:", err)
			os.Exit(1)
		}
	case "digest":
		d, err := policy.BundleDigest()
		if err != nil {
			fmt.Fprintln(os.Stderr, "policybundle:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, d)
	default:
		fmt.Fprintf(os.Stderr, "policybundle: unknown mode %q (want \"manifest\" or \"digest\")\n", mode)
		os.Exit(2)
	}
}
