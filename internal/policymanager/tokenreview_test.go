package policymanager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// reviewerWithReactor builds an InternalTokenAuthenticator over the client-go
// fake clientset with a PrependReactor that fully drives the TokenReview
// "create" response, so the audience-bound validation path is exercised without
// any real apiserver (FIPS build posture: no network). expectedUsername ""
// disables subject pinning (valid for most unit tests that focus on other
// invariants).
func reviewerWithReactor(audience, expectedUsername string, react func() (runtime.Object, error)) *InternalTokenAuthenticator {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(clienttesting.Action) (bool, runtime.Object, error) {
		obj, err := react()
		return true, obj, err
	})
	return NewInternalTokenAuthenticator(cs.AuthenticationV1().TokenReviews(), audience, expectedUsername, zap.NewNop())
}

const webhookSA = "system:serviceaccount:kube-policies:admission-webhook"

func TestInternalTokenAuthenticator_ValidAudienceBound_Accepted(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{"policy-manager"},
				User:          authenticationv1.UserInfo{Username: webhookSA},
			},
		}, nil
	})

	ok, username, err := a.Authenticate(context.Background(), "any-projected-token")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, webhookSA, username)
}

// TestInternalTokenAuthenticator_WrongAudience_Rejected proves we do NOT trust
// Status.Authenticated alone: a token authenticated for a different audience
// (e.g. the apiserver) must be rejected.
func TestInternalTokenAuthenticator_WrongAudience_Rejected(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{"https://kubernetes.default.svc"},
				User:          authenticationv1.UserInfo{Username: "system:serviceaccount:default:generic"},
			},
		}, nil
	})

	ok, username, err := a.Authenticate(context.Background(), "generic-token")
	require.NoError(t, err)
	assert.False(t, ok, "a token authenticated for the wrong audience must be rejected")
	assert.Empty(t, username)
}

func TestInternalTokenAuthenticator_GenericSAToken_Rejected(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Authenticated: false},
		}, nil
	})

	ok, _, err := a.Authenticate(context.Background(), "unauth-token")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestInternalTokenAuthenticator_Expired_Rejected_WithCorrectAudience is the
// FIX-4 mutation-killing variant: the reactor returns Authenticated:false AND
// the correct audience so the audience check cannot mask an absent Authenticated
// guard. Deleting `if !res.Status.Authenticated` must make this test fail.
func TestInternalTokenAuthenticator_Expired_Rejected_WithCorrectAudience(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Audiences:     []string{"policy-manager"}, // correct audience — Authenticated gate is load-bearing
				Error:         "token has expired",
			},
		}, nil
	})

	ok, _, err := a.Authenticate(context.Background(), "expired-token")
	require.NoError(t, err, "expired token must be a clean negative, not an error")
	assert.False(t, ok, "Authenticated:false must reject even when the audience matches")
}

// TestInternalTokenAuthenticator_Expired_Rejected is the original test retained
// as a regression guard (Authenticated:false, empty audiences).
func TestInternalTokenAuthenticator_Expired_Rejected(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "[invalid bearer token, token has expired]",
			},
		}, nil
	})

	ok, _, err := a.Authenticate(context.Background(), "expired-token")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestInternalTokenAuthenticator_NilAudiences_Rejected is the FIX-4 empty/nil
// audience mutation-kill: Status{Authenticated:true, Audiences:nil} must NOT
// wildcard-match. audienceIntersects returns false for nil tokenAud — this test
// proves it.
func TestInternalTokenAuthenticator_NilAudiences_Rejected(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     nil, // MUST NOT wildcard-match
				User:          authenticationv1.UserInfo{Username: webhookSA},
			},
		}, nil
	})

	ok, _, err := a.Authenticate(context.Background(), "token-with-nil-aud")
	require.NoError(t, err)
	assert.False(t, ok, "nil/empty Status.Audiences must not wildcard-match the expected audience")
}

// TestInternalTokenAuthenticator_APIError_FailsClosed proves a TokenReview API
// error surfaces as a non-nil err from Authenticate so the caller fails closed.
func TestInternalTokenAuthenticator_APIError_FailsClosed(t *testing.T) {
	a := reviewerWithReactor("policy-manager", "", func() (runtime.Object, error) {
		return nil, errors.New("apiserver unreachable")
	})

	ok, username, err := a.Authenticate(context.Background(), "any-token")
	require.Error(t, err, "a TokenReview API error must surface so the caller fails closed")
	assert.False(t, ok)
	assert.Empty(t, username)
}

// TestInternalTokenAuthenticator_SubjectPin_WrongUsername_Rejected proves that
// a valid audience-bound token from a DIFFERENT ServiceAccount is rejected when
// subject pinning is configured.
func TestInternalTokenAuthenticator_SubjectPin_WrongUsername_Rejected(t *testing.T) {
	a := reviewerWithReactor("policy-manager", webhookSA, func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{"policy-manager"},
				User:          authenticationv1.UserInfo{Username: "system:serviceaccount:default:other-sa"},
			},
		}, nil
	})

	ok, _, err := a.Authenticate(context.Background(), "other-sa-token")
	require.NoError(t, err, "subject mismatch is a clean negative, not an API error")
	assert.False(t, ok, "correct audience but wrong subject must be rejected when pinning is enabled")
}

// TestInternalTokenAuthenticator_SubjectPin_Correct_Accepted proves the happy
// path when subject pinning is enabled and the token carries the expected SA.
func TestInternalTokenAuthenticator_SubjectPin_Correct_Accepted(t *testing.T) {
	a := reviewerWithReactor("policy-manager", webhookSA, func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     []string{"policy-manager"},
				User:          authenticationv1.UserInfo{Username: webhookSA},
			},
		}, nil
	})

	ok, gotUsername, err := a.Authenticate(context.Background(), "correct-projected-token")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, webhookSA, gotUsername)
}
