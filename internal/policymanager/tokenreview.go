package policymanager

import (
	"context"
	"sync/atomic"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedauthnv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

// tokenReviewer is the narrow seam InternalTokenAuthenticator depends on,
// mirroring the oidcVerifier seam in auth_middleware.go. It is satisfied by a
// real authenticationv1.TokenReviewInterface in production and by the client-go
// fake (with a PrependReactor) in tests, so the TokenReview validation path can
// be exercised without a live apiserver.
type tokenReviewer interface {
	Create(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error)
}

// InternalTokenAuthenticator validates an inbound bearer token presented on the
// webhook -> policy-manager decisions channel (/api/v1/decisions/internal) by
// submitting it to the Kubernetes TokenReview API (IAM-WU-11).
//
// It is audience-AND-subject-bound: the review is created with the expected
// audience in Spec.Audiences, and a verdict is only accepted when the apiserver
// both authenticated the token AND echoed the expected audience back in
// Status.Audiences AND the Status.User.Username matches the expected subject
// (when configured). Trusting Status.Authenticated alone would admit any valid
// ServiceAccount token in the cluster regardless of which audience it was
// projected for; trusting audience alone would admit any pod that happens to
// request the same audience. The subject pin ties the credential to the webhook's
// specific ServiceAccount identity (AU-2/AU-3).
type InternalTokenAuthenticator struct {
	reviewer         tokenReviewer
	audience         string
	expectedUsername string // empty → subject check disabled (log a one-time warning)
	logger           *zap.Logger
	subjectWarnOnce  atomic.Bool // guards the one-time no-subject warning
}

// NewInternalTokenAuthenticator builds an authenticator over a production
// authenticationv1.TokenReviewInterface (obtained from
// kubernetes.Clientset.AuthenticationV1().TokenReviews()). audience is the
// literal audience the projected webhook token must carry (e.g. "policy-manager").
// expectedUsername, when non-empty, pins the accepted ServiceAccount identity
// to the webhook's SA username (e.g.
// "system:serviceaccount:<ns>:<webhook-sa-name>"); an empty string disables
// subject pinning and logs a one-time startup warning.
func NewInternalTokenAuthenticator(reviews typedauthnv1.TokenReviewInterface, audience, expectedUsername string, logger *zap.Logger) *InternalTokenAuthenticator {
	if logger == nil {
		logger = zap.NewNop()
	}
	a := &InternalTokenAuthenticator{
		reviewer:         reviews,
		audience:         audience,
		expectedUsername: expectedUsername,
		logger:           logger,
	}
	if expectedUsername == "" {
		// Log immediately at construction so the operator sees this on startup,
		// not only after the first token arrives.
		logger.Warn("internal decisions channel: subject pinning is DISABLED (POLICY_MANAGER_INTERNAL_SUBJECT not set). Any ServiceAccount token bound to the expected audience will be accepted. Set POLICY_MANAGER_INTERNAL_SUBJECT to the webhook SA username to restrict acceptance to that identity (IAM-WU-11).")
	}
	return a
}

// Authenticate validates bearer via the TokenReview API.
//
// Return contract (fail-closed): a non-nil err signals that the verdict could
// NOT be established (TokenReview API error). The caller MUST reject the request
// and MUST NOT fall through to any other auth path on a non-nil err. A nil err
// with ok==false is a CLEAN negative verdict (token not authenticated, wrong
// audience, or wrong subject) on which the caller may consult a configured
// static fallback.
//
// ok is true only when ALL of the following hold:
//  1. Status.Authenticated is true.
//  2. Status.Audiences intersects the expected audience — audienceIntersects
//     returns false for nil/empty tokenAud so a missing audience field cannot
//     wildcard-match (load-bearing).
//  3. expectedUsername is "" OR Status.User.Username == expectedUsername.
//
// Token material is never logged; only verdicts/usernames/errors are (AU-2/AU-3).
func (a *InternalTokenAuthenticator) Authenticate(ctx context.Context, bearer string) (ok bool, username string, err error) {
	tr := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     bearer,
			Audiences: []string{a.audience},
		},
	}
	res, err := a.reviewer.Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		// Fail-closed signal: the verdict is unknown. Never log token material.
		return false, "", err
	}
	if !res.Status.Authenticated {
		return false, "", nil
	}
	// audienceIntersects returns false for nil/empty tokenAud — an empty
	// Status.Audiences field MUST NOT wildcard-match our expected audience.
	if !audienceIntersects(res.Status.Audiences, []string{a.audience}) {
		return false, "", nil
	}
	// Subject pinning (AU-2/AU-3): reject tokens from identities other than
	// the expected webhook SA, preventing any other SA that happened to
	// obtain an audience=policy-manager token from passing.
	if a.expectedUsername != "" && res.Status.User.Username != a.expectedUsername {
		a.logger.Warn("internal decisions ingest: TokenReview authenticated but subject mismatch; rejecting",
			zap.String("got_username", res.Status.User.Username),
			// expected_username is not secret — it is the webhook SA name
			zap.String("expected_username", a.expectedUsername),
		)
		return false, "", nil
	}
	a.logger.Info("internal decisions ingest: TokenReview authenticated",
		zap.String("username", res.Status.User.Username),
	)
	return true, res.Status.User.Username, nil
}
