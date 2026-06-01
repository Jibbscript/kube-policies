package audit

import (
	"encoding/json"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
)

// Audit-record redaction (AUD-WU-17, NIST AU-3(1) / SI-12).
//
// The durable Event persists the full admitted object (Object/OldObject) so an
// auditor can see exactly what was requested. For Secret-bearing kinds and any
// object carrying credential-like keys, that payload would otherwise write
// cleartext secrets to the audit log. maybeRedact rewrites those payloads to a
// fixed placeholder BEFORE the record is sealed/written (see flushEvents), so
// the on-disk record — and the HMAC computed over it — never contains the
// sensitive material. The streaming PublicEvent already omits Object entirely;
// this closes the same gap on the durable path.

const redactedPlaceholder = "[REDACTED]"

// sensitiveKeySubstrings: any object key whose lower-cased form contains one of
// these has its scalar value replaced. Conservative and value-level, so the
// record's structure (which key was set) is preserved for the auditor while the
// secret value is not.
var sensitiveKeySubstrings = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"privatekey", "private_key", "credential", "bearer",
	"client_secret", "clientsecret", "tls.key", "dockerconfigjson",
	"session", "cookie",
}

// maybeRedact returns an Event whose Object/OldObject have had Secret data and
// credential-like values replaced, when config.RedactObjects is enabled. The
// input event is never mutated — a shallow copy is returned with fresh
// RawExtensions so any other holder of the original (e.g. a streamed event)
// is unaffected.
func (l *Logger) maybeRedact(event *Event) *Event {
	if l == nil || l.config == nil || !l.config.RedactObjects {
		return event
	}
	if event.Object == nil && event.OldObject == nil {
		return event
	}

	isSecret := strings.EqualFold(event.Kind.Kind, "Secret")
	redactedObj := redactRawExtension(event.Object, isSecret)
	redactedOld := redactRawExtension(event.OldObject, isSecret)
	if redactedObj == event.Object && redactedOld == event.OldObject {
		return event // nothing changed
	}

	cp := *event // shallow copy; scalar/slice fields shared, payload swapped
	cp.Object = redactedObj
	cp.OldObject = redactedOld
	return &cp
}

// redactRawExtension parses re.Raw, redacts it, and returns a new RawExtension.
// It returns the input unchanged when re is nil/empty or not a JSON object, or
// when redaction produced no change.
func redactRawExtension(re *runtime.RawExtension, secretKind bool) *runtime.RawExtension {
	if re == nil || len(re.Raw) == 0 {
		return re
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(re.Raw, &obj); err != nil {
		// Not a JSON object (or malformed). To stay fail-safe for SI-12, replace
		// an unparseable payload wholesale rather than risk persisting a secret
		// we could not introspect.
		out, _ := json.Marshal(redactedPlaceholder)
		return &runtime.RawExtension{Raw: out}
	}

	// kind may live on the object itself even when the Event.Kind was not set.
	if k, ok := obj["kind"].(string); ok && strings.EqualFold(k, "Secret") {
		secretKind = true
	}
	if secretKind {
		redactSecretData(obj)
	}
	redactSensitiveKeys(obj)

	out, err := json.Marshal(obj)
	if err != nil {
		return re
	}
	return &runtime.RawExtension{Raw: out}
}

// redactSecretData fully redacts the data/stringData maps of a core/v1 Secret.
func redactSecretData(obj map[string]interface{}) {
	for _, field := range []string{"data", "stringData"} {
		if m, ok := obj[field].(map[string]interface{}); ok {
			for k := range m {
				m[k] = redactedPlaceholder
			}
		}
	}
}

// redactSensitiveKeys recursively replaces scalar values whose key looks like a
// credential. Maps and slices are walked; matched values are replaced regardless
// of depth.
func redactSensitiveKeys(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if isSensitiveKey(k) {
				if _, isMap := val.(map[string]interface{}); !isMap {
					if _, isSlice := val.([]interface{}); !isSlice {
						t[k] = redactedPlaceholder
						continue
					}
				}
			}
			redactSensitiveKeys(val)
		}
	case []interface{}:
		for _, item := range t {
			redactSensitiveKeys(item)
		}
	}
}

func isSensitiveKey(key string) bool {
	lk := strings.ToLower(key)
	for _, s := range sensitiveKeySubstrings {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}
