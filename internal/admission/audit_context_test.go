package admission

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// AUD-WU-01/02/20: the controller populates AU-3 source attribution (from the
// HTTP request), the AU-8 received timestamp (UTC), and the AU-12(1) correlation
// id (the AdmissionRequest UID) on the audit context.
func TestNewAuditContext_PopulatesAttribution(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/validate", nil)
	req.RemoteAddr = "10.1.2.3:54321"
	req.Header.Set("User-Agent", "kube-apiserver/v1.31.2")
	c.Request = req

	admReq := &admissionv1.AdmissionRequest{
		UID:       types.UID("abc-123"),
		Namespace: "prod",
		Name:      "web",
		Operation: admissionv1.Create,
		Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		UserInfo:  authenticationv1.UserInfo{Username: "system:serviceaccount:prod:deployer"},
	}

	start := time.Now()
	ctrl := &Controller{}
	ac := ctrl.newAuditContext(c, admReq, start)

	if ac.SourceIP == "" {
		t.Error("source_ip must be populated from the HTTP peer")
	}
	if ac.SourceIP != "10.1.2.3" {
		t.Errorf("source_ip = %q, want 10.1.2.3", ac.SourceIP)
	}
	if ac.UserAgent != "kube-apiserver/v1.31.2" {
		t.Errorf("user_agent = %q", ac.UserAgent)
	}
	if ac.RequestURI != "/validate" {
		t.Errorf("request_uri = %q", ac.RequestURI)
	}
	if ac.CorrelationID != "abc-123" {
		t.Errorf("correlation_id = %q, want the request UID", ac.CorrelationID)
	}
	if ac.RequestReceivedTimestamp.Location() != time.UTC {
		t.Errorf("request_received_timestamp must be UTC, got %v", ac.RequestReceivedTimestamp.Location())
	}
	if ac.RequestID != "abc-123" {
		t.Errorf("request_id = %q", ac.RequestID)
	}
}
