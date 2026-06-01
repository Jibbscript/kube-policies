package policymanager

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/auth"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

// Manager handles policy management operations
type Manager struct {
	config     *config.Config
	logger     *zap.Logger
	policies   map[string]*policy.Policy
	bundles    map[string]*PolicyBundle
	exceptions map[string]*Exception
	mutex      sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc

	// M2 live-ticker: fan-out pub-sub bus, bounded recent-event ring, and the
	// constant-time verifier for the shared bearer secret that guards
	// POST /api/v1/decisions/internal.
	bus           *audit.Bus
	recentRing    *Ring
	internalToken *auth.TokenVerifier

	// internalReviewer validates an inbound projected ServiceAccount token on
	// POST /api/v1/decisions/internal via the Kubernetes TokenReview API
	// (IAM-WU-11). When non-nil it is the primary, audience-bound authenticator
	// for that endpoint; internalToken remains the opt-in static fallback for
	// non-cluster/demo deployments. nil leaves behavior exactly as before
	// (static-token only).
	internalReviewer *InternalTokenAuthenticator

	// auditLogger records a ConfigurationChange audit event for every persisting
	// management-plane mutation (IAM-WU-14, AU-2/AU-3/AC-6). It is installed via
	// SetAuditLogger after construction so existing NewManager(cfg, log) callers
	// (tests, alternate entry points) are unaffected. nil disables audit
	// attribution entirely — every mutation handler guards on it — so a manager
	// built without an audit logger behaves exactly as before.
	auditLogger *audit.Logger
}

// PolicyBundle represents a collection of policies
type PolicyBundle struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Policies    []string               `json:"policies"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Exception represents a policy exception
type Exception struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	PolicyID      string                 `json:"policy_id"`
	RuleID        string                 `json:"rule_id,omitempty"`
	Scope         ExceptionScope         `json:"scope"`
	Justification string                 `json:"justification"`
	Approver      string                 `json:"approver"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
	Status        string                 `json:"status"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// ExceptionScope defines the scope of a policy exception
type ExceptionScope struct {
	Namespaces []string `json:"namespaces,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Users      []string `json:"users,omitempty"`
	Groups     []string `json:"groups,omitempty"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID          string                 `json:"id"`
	Framework   string                 `json:"framework"`
	Period      string                 `json:"period"`
	Status      string                 `json:"status"`
	Summary     ComplianceSummary      `json:"summary"`
	Violations  []ComplianceViolation  `json:"violations"`
	Metadata    map[string]interface{} `json:"metadata"`
	GeneratedAt time.Time              `json:"generated_at"`
}

// ComplianceSummary provides a summary of compliance status
type ComplianceSummary struct {
	TotalChecks    int     `json:"total_checks"`
	PassedChecks   int     `json:"passed_checks"`
	FailedChecks   int     `json:"failed_checks"`
	ComplianceRate float64 `json:"compliance_rate"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ControlID   string    `json:"control_id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Resource    string    `json:"resource"`
	Namespace   string    `json:"namespace"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewManager creates a new policy manager. The bundled-default policies
// shipped by the engine (see internal/policy/engine.go::loadDefaultPolicies)
// are pre-loaded into the manager so /api/v1/policies and the Playground
// surface the same baseline the admission webhook evaluates. The engine
// remains the single source of truth — the manager only mirrors it.
func NewManager(config *config.Config, logger *zap.Logger) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:     config,
		logger:     logger,
		policies:   make(map[string]*policy.Policy),
		bundles:    make(map[string]*PolicyBundle),
		exceptions: make(map[string]*Exception),
		ctx:        ctx,
		cancel:     cancel,
		bus:        audit.NewBus(256, logger),
		recentRing: NewRing(256),
	}

	// Mirror the engine's bundled defaults into the manager registry so
	// API consumers (dashboard SPA, future CLIs) see the same policies the
	// webhook would enforce. Failure here is non-fatal — an empty registry
	// is still a valid state — but we log loudly so operators notice.
	bootstrapEngine, err := policy.NewEngine(&config.Policy, logger)
	if err != nil {
		logger.Warn("could not bootstrap engine to mirror bundled defaults; manager will start with an empty policy registry",
			zap.Error(err),
		)
	} else {
		for _, p := range bootstrapEngine.ListPolicies() {
			manager.policies[p.ID] = p
		}
		logger.Info("policy manager seeded from engine bundled defaults",
			zap.Int("count", len(manager.policies)),
		)
	}

	return manager, nil
}

// SetInternalToken sets the shared bearer secret used to authenticate
// POST /api/v1/decisions/internal requests from the admission webhook.
// An empty token disables the endpoint (every request returns 401).
func (m *Manager) SetInternalToken(token string) {
	m.internalToken = auth.NewTokenVerifier(token)
}

// SetInternalTokens configures the internal-token verifier with a current and
// an optional previous token, supporting a zero-downtime rotation window in
// which both are accepted (CRY-WU-14). An empty previous token is ignored; an
// empty current token disables the endpoint.
func (m *Manager) SetInternalTokens(current, previous string) {
	m.internalToken = auth.NewTokenVerifier(current, previous)
}

// SetInternalTokenReviewer installs the audience-bound TokenReview authenticator
// for POST /api/v1/decisions/internal (IAM-WU-11). When set, an inbound bearer
// is validated against the Kubernetes TokenReview API first; a clean negative
// verdict (token not authenticated / wrong audience) may then fall through to
// the static internalToken verifier if one is configured, but a TokenReview API
// error always rejects (fail closed). A nil reviewer leaves the endpoint on the
// static-token-only path. Independent of SetInternalTokens, which is left
// unchanged so the static fallback is always available.
func (m *Manager) SetInternalTokenReviewer(reviewer *InternalTokenAuthenticator) {
	m.internalReviewer = reviewer
}

// SetAuditLogger installs the audit.Logger that records a ConfigurationChange
// event for every persisting management-plane mutation (IAM-WU-14). It is set
// after construction (mirroring SetInternalToken*/SetInternalTokenReviewer) so
// no existing NewManager(cfg, log) caller is forced to change. A nil logger —
// or never calling this — leaves attribution off: every mutation handler guards
// on m.auditLogger != nil, so behavior is identical to before.
func (m *Manager) SetAuditLogger(l *audit.Logger) {
	m.auditLogger = l
}

// Start starts the policy manager background processes
func (m *Manager) Start(ctx context.Context) {
	m.logger.Info("Starting policy manager")

	// Start policy synchronization
	go m.syncPolicies(ctx)

	// Start exception monitoring
	go m.monitorExceptions(ctx)

	<-ctx.Done()
	m.cancel() // release the manager-owned context the constructor created
	m.bus.Close()
	m.logger.Info("Policy manager stopped")
}

// syncPolicies synchronizes policies from external sources
func (m *Manager) syncPolicies(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Implement policy synchronization logic
			m.logger.Debug("Synchronizing policies")
		}
	}
}

// monitorExceptions monitors policy exceptions for expiration
func (m *Manager) monitorExceptions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkExpiredExceptions()
		}
	}
}

// checkExpiredExceptions checks for and handles expired exceptions
func (m *Manager) checkExpiredExceptions() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	for id, exception := range m.exceptions {
		if exception.ExpiresAt != nil && exception.ExpiresAt.Before(now) {
			exception.Status = "expired"
			m.logger.Info("Exception expired",
				zap.String("exception_id", id),
				zap.String("policy_id", exception.PolicyID),
			)
		}
	}
}

// API Handlers

// ListPolicies handles GET /api/v1/policies
func (m *Manager) ListPolicies(c *gin.Context) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policies := make([]*policy.Policy, 0, len(m.policies))
	for _, p := range m.policies {
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		"total":    len(policies),
	})
}

// GetPolicy handles GET /api/v1/policies/:id
func (m *Manager) GetPolicy(c *gin.Context) {
	id := c.Param("id")

	m.mutex.RLock()
	policy, exists := m.policies[id]
	m.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// CreatePolicy handles POST /api/v1/policies
func (m *Manager) CreatePolicy(c *gin.Context) {
	var newPolicy policy.Policy
	if err := c.ShouldBindJSON(&newPolicy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate ID if not provided
	if newPolicy.ID == "" {
		newPolicy.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	newPolicy.CreatedAt = now
	newPolicy.UpdatedAt = now

	// Validate policy
	if err := m.validatePolicy(&newPolicy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	m.mutex.Lock()
	m.policies[newPolicy.ID] = &newPolicy
	m.mutex.Unlock()

	m.logger.Info("Policy created",
		zap.String("policy_id", newPolicy.ID),
		zap.String("policy_name", newPolicy.Name),
	)

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "CREATE", "policy", newPolicy.ID, map[string]interface{}{
			"source_ip":   c.ClientIP(),
			"policy_name": newPolicy.Name,
		})
	}

	c.JSON(http.StatusCreated, newPolicy)
}

// UpdatePolicy handles PUT /api/v1/policies/:id
func (m *Manager) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")

	var updatedPolicy policy.Policy
	if err := c.ShouldBindJSON(&updatedPolicy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	m.mutex.Lock()

	existingPolicy, exists := m.policies[id]
	if !exists {
		m.mutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Preserve creation time and ID
	updatedPolicy.ID = id
	updatedPolicy.CreatedAt = existingPolicy.CreatedAt
	updatedPolicy.UpdatedAt = time.Now()

	// Validate policy
	if err := m.validatePolicy(&updatedPolicy); err != nil {
		m.mutex.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	m.policies[id] = &updatedPolicy
	m.mutex.Unlock()

	m.logger.Info("Policy updated",
		zap.String("policy_id", id),
		zap.String("policy_name", updatedPolicy.Name),
	)

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "UPDATE", "policy", id, map[string]interface{}{
			"source_ip":   c.ClientIP(),
			"policy_name": updatedPolicy.Name,
		})
	}

	c.JSON(http.StatusOK, updatedPolicy)
}

// DeletePolicy handles DELETE /api/v1/policies/:id
func (m *Manager) DeletePolicy(c *gin.Context) {
	id := c.Param("id")

	m.mutex.Lock()

	if _, exists := m.policies[id]; !exists {
		m.mutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	delete(m.policies, id)
	m.mutex.Unlock()

	m.logger.Info("Policy deleted", zap.String("policy_id", id))

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "DELETE", "policy", id, map[string]interface{}{
			"source_ip": c.ClientIP(),
		})
	}

	c.JSON(http.StatusNoContent, nil)
}

// TestPolicy handles POST /api/v1/policies/:id/test.
// Evaluates the given admission object (bare K8s object or full AdmissionReview)
// against ONLY the picked policy's rules via policy.NewEvaluatorForPolicy.
func (m *Manager) TestPolicy(c *gin.Context) {
	m.testPolicyImpl(c)
}

// ValidatePolicy handles POST /api/v1/policies/validate
func (m *Manager) ValidatePolicy(c *gin.Context) {
	var policyToValidate policy.Policy
	if err := c.ShouldBindJSON(&policyToValidate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := m.validatePolicy(&policyToValidate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "Policy is valid",
	})
}

// DeployPolicy handles POST /api/v1/policies/:id/deploy.
// Stub: cluster deployment is not yet implemented.
//
// IAM-WU-14: when this is un-stubbed and begins mutating cluster state, it MUST
// emit m.auditLogger.LogConfigChange(userInfoFromContext(c), "DEPLOY", "policy",
// id, ...) in the success path, like the seven CRUD handlers. No audit call is
// added now because a 501 stub persists nothing — recording a ConfigurationChange
// for a no-op would be a misleading event.
func (m *Manager) DeployPolicy(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "policy deployment is not yet implemented"})
}

// GetPolicyStatus handles GET /api/v1/policies/:id/status.
// Stub: live status (last evaluated, evaluation count, violation count) is not yet wired to runtime telemetry.
func (m *Manager) GetPolicyStatus(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "policy status reporting is not yet implemented"})
}

// Bundle management handlers

// ListBundles handles GET /api/v1/bundles
func (m *Manager) ListBundles(c *gin.Context) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	bundles := make([]*PolicyBundle, 0, len(m.bundles))
	for _, bundle := range m.bundles {
		bundles = append(bundles, bundle)
	}

	c.JSON(http.StatusOK, gin.H{
		"bundles": bundles,
		"total":   len(bundles),
	})
}

// GetBundle handles GET /api/v1/bundles/:id
func (m *Manager) GetBundle(c *gin.Context) {
	id := c.Param("id")

	m.mutex.RLock()
	bundle, exists := m.bundles[id]
	m.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Bundle not found"})
		return
	}

	c.JSON(http.StatusOK, bundle)
}

// CreateBundle handles POST /api/v1/bundles
func (m *Manager) CreateBundle(c *gin.Context) {
	var newBundle PolicyBundle
	if err := c.ShouldBindJSON(&newBundle); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if newBundle.ID == "" {
		newBundle.ID = uuid.New().String()
	}

	now := time.Now()
	newBundle.CreatedAt = now
	newBundle.UpdatedAt = now

	m.mutex.Lock()
	m.bundles[newBundle.ID] = &newBundle
	m.mutex.Unlock()

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "CREATE", "bundle", newBundle.ID, map[string]interface{}{
			"source_ip":   c.ClientIP(),
			"bundle_name": newBundle.Name,
		})
	}

	c.JSON(http.StatusCreated, newBundle)
}

// Exception management handlers

// ListExceptions handles GET /api/v1/exceptions
func (m *Manager) ListExceptions(c *gin.Context) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	exceptions := make([]*Exception, 0, len(m.exceptions))
	for _, exception := range m.exceptions {
		exceptions = append(exceptions, exception)
	}

	c.JSON(http.StatusOK, gin.H{
		"exceptions": exceptions,
		"total":      len(exceptions),
	})
}

// CreateException handles POST /api/v1/exceptions
func (m *Manager) CreateException(c *gin.Context) {
	var newException Exception
	if err := c.ShouldBindJSON(&newException); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if newException.ID == "" {
		newException.ID = uuid.New().String()
	}

	now := time.Now()
	newException.CreatedAt = now
	newException.UpdatedAt = now
	newException.Status = "pending"

	m.mutex.Lock()
	m.exceptions[newException.ID] = &newException
	m.mutex.Unlock()

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "CREATE", "exception", newException.ID, map[string]interface{}{
			"source_ip": c.ClientIP(),
			"policy_id": newException.PolicyID,
		})
	}

	c.JSON(http.StatusCreated, newException)
}

// UpdateException handles PUT /api/v1/exceptions/:id
func (m *Manager) UpdateException(c *gin.Context) {
	id := c.Param("id")

	var updatedException Exception
	if err := c.ShouldBindJSON(&updatedException); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	m.mutex.Lock()

	existingException, exists := m.exceptions[id]
	if !exists {
		m.mutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Exception not found"})
		return
	}

	updatedException.ID = id
	updatedException.CreatedAt = existingException.CreatedAt
	updatedException.UpdatedAt = time.Now()

	m.exceptions[id] = &updatedException
	m.mutex.Unlock()

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "UPDATE", "exception", id, map[string]interface{}{
			"source_ip": c.ClientIP(),
			"policy_id": updatedException.PolicyID,
		})
	}

	c.JSON(http.StatusOK, updatedException)
}

// DeleteException handles DELETE /api/v1/exceptions/:id
func (m *Manager) DeleteException(c *gin.Context) {
	id := c.Param("id")

	m.mutex.Lock()

	if _, exists := m.exceptions[id]; !exists {
		m.mutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Exception not found"})
		return
	}

	delete(m.exceptions, id)
	m.mutex.Unlock()

	if m.auditLogger != nil {
		m.auditLogger.LogConfigChange(userInfoFromContext(c), "DELETE", "exception", id, map[string]interface{}{
			"source_ip": c.ClientIP(),
		})
	}

	c.JSON(http.StatusNoContent, nil)
}

// Compliance reporting handlers

// ListComplianceReports handles GET /api/v1/compliance/reports.
// Stub: report generation and storage are not yet implemented.
func (m *Manager) ListComplianceReports(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "compliance reporting is not yet implemented"})
}

// GenerateComplianceReport handles POST /api/v1/compliance/reports.
// Stub: report generation is not yet implemented.
//
// IAM-WU-14: when this is un-stubbed and begins persisting a generated report,
// it MUST emit m.auditLogger.LogConfigChange(userInfoFromContext(c), "GENERATE",
// "compliance_report", reportID, ...) in the success path. No audit call is
// added now because a 501 stub persists nothing.
func (m *Manager) GenerateComplianceReport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "compliance reporting is not yet implemented"})
}

// ListComplianceFrameworks handles GET /api/v1/compliance/frameworks.
// Stub: framework catalog is not yet sourced from configuration or a registry.
func (m *Manager) ListComplianceFrameworks(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "compliance framework catalog is not yet implemented"})
}

// validatePolicy validates a policy configuration. In addition to the field
// presence checks (name, rules, rule.name, rule.rego), every rule's Rego
// body is compiled via the OPA prepared-query path so /policies/validate
// catches syntax errors before a policy is persisted or evaluated.
//
// Compilation errors are wrapped as "rego syntax error: <opa msg>" — a test
// assertion that checks for the substring "syntax" matches every OPA parse
// failure regardless of OPA's internal error prefix.
func (m *Manager) validatePolicy(p *policy.Policy) error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}

	for i := range p.Rules {
		rule := &p.Rules[i]
		if rule.Name == "" {
			return fmt.Errorf("rule name is required")
		}
		if rule.Rego == "" {
			return fmt.Errorf("rule rego is required")
		}
		if err := compileRego(p.ID, rule); err != nil {
			return err
		}
	}

	return nil
}
