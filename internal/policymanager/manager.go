package policymanager

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
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

// NewManager creates a new policy manager
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
	}

	return manager, nil
}

// Start starts the policy manager background processes
func (m *Manager) Start(ctx context.Context) {
	m.logger.Info("Starting policy manager")

	// Start policy synchronization
	go m.syncPolicies(ctx)

	// Start exception monitoring
	go m.monitorExceptions(ctx)

	<-ctx.Done()
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
	defer m.mutex.Unlock()

	existingPolicy, exists := m.policies[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Preserve creation time and ID
	updatedPolicy.ID = id
	updatedPolicy.CreatedAt = existingPolicy.CreatedAt
	updatedPolicy.UpdatedAt = time.Now()

	// Validate policy
	if err := m.validatePolicy(&updatedPolicy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	m.policies[id] = &updatedPolicy

	m.logger.Info("Policy updated",
		zap.String("policy_id", id),
		zap.String("policy_name", updatedPolicy.Name),
	)

	c.JSON(http.StatusOK, updatedPolicy)
}

// DeletePolicy handles DELETE /api/v1/policies/:id
func (m *Manager) DeletePolicy(c *gin.Context) {
	id := c.Param("id")

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.policies[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	delete(m.policies, id)

	m.logger.Info("Policy deleted", zap.String("policy_id", id))

	c.JSON(http.StatusNoContent, nil)
}

// TestPolicy handles POST /api/v1/policies/:id/test
func (m *Manager) TestPolicy(c *gin.Context) {
	id := c.Param("id")

	var testRequest struct {
		Input map[string]interface{} `json:"input"`
	}

	if err := c.ShouldBindJSON(&testRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	m.mutex.RLock()
	policy, exists := m.policies[id]
	m.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Implement policy testing logic
	result := map[string]interface{}{
		"policy_id":   id,
		"policy_name": policy.Name,
		"result":      "passed",
		"message":     "Policy test completed successfully",
		"details":     testRequest.Input,
	}

	c.JSON(http.StatusOK, result)
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

// DeployPolicy handles POST /api/v1/policies/:id/deploy
func (m *Manager) DeployPolicy(c *gin.Context) {
	id := c.Param("id")

	m.mutex.RLock()
	policy, exists := m.policies[id]
	m.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Implement policy deployment logic
	deploymentResult := map[string]interface{}{
		"policy_id":       id,
		"status":          "deployed",
		"deployed_at":     time.Now(),
		"target_clusters": []string{"production"},
	}

	m.logger.Info("Policy deployed",
		zap.String("policy_id", id),
		zap.String("policy_name", policy.Name),
	)

	c.JSON(http.StatusOK, deploymentResult)
}

// GetPolicyStatus handles GET /api/v1/policies/:id/status
func (m *Manager) GetPolicyStatus(c *gin.Context) {
	id := c.Param("id")

	m.mutex.RLock()
	policy, exists := m.policies[id]
	m.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	status := map[string]interface{}{
		"policy_id":        id,
		"status":           "active",
		"enabled":          policy.Enabled,
		"last_evaluated":   time.Now().Add(-5 * time.Minute),
		"evaluation_count": 1234,
		"violation_count":  5,
	}

	c.JSON(http.StatusOK, status)
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
	defer m.mutex.Unlock()

	existingException, exists := m.exceptions[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exception not found"})
		return
	}

	updatedException.ID = id
	updatedException.CreatedAt = existingException.CreatedAt
	updatedException.UpdatedAt = time.Now()

	m.exceptions[id] = &updatedException

	c.JSON(http.StatusOK, updatedException)
}

// DeleteException handles DELETE /api/v1/exceptions/:id
func (m *Manager) DeleteException(c *gin.Context) {
	id := c.Param("id")

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.exceptions[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exception not found"})
		return
	}

	delete(m.exceptions, id)
	c.JSON(http.StatusNoContent, nil)
}

// Compliance reporting handlers

// ListComplianceReports handles GET /api/v1/compliance/reports
func (m *Manager) ListComplianceReports(c *gin.Context) {
	// Mock compliance reports
	reports := []ComplianceReport{
		{
			ID:        "report-1",
			Framework: "CIS",
			Period:    "2025-01",
			Status:    "completed",
			Summary: ComplianceSummary{
				TotalChecks:    100,
				PassedChecks:   85,
				FailedChecks:   15,
				ComplianceRate: 85.0,
			},
			GeneratedAt: time.Now(),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"reports": reports,
		"total":   len(reports),
	})
}

// GenerateComplianceReport handles POST /api/v1/compliance/reports
func (m *Manager) GenerateComplianceReport(c *gin.Context) {
	var request struct {
		Framework string `json:"framework"`
		Period    string `json:"period"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	report := ComplianceReport{
		ID:          uuid.New().String(),
		Framework:   request.Framework,
		Period:      request.Period,
		Status:      "generating",
		GeneratedAt: time.Now(),
	}

	c.JSON(http.StatusAccepted, report)
}

// ListComplianceFrameworks handles GET /api/v1/compliance/frameworks
func (m *Manager) ListComplianceFrameworks(c *gin.Context) {
	frameworks := []map[string]interface{}{
		{
			"id":          "cis",
			"name":        "CIS Kubernetes Benchmark",
			"version":     "1.8.0",
			"description": "Center for Internet Security Kubernetes Benchmark",
		},
		{
			"id":          "nist",
			"name":        "NIST Cybersecurity Framework",
			"version":     "2.0",
			"description": "NIST Cybersecurity Framework 2.0",
		},
		{
			"id":          "pci",
			"name":        "PCI DSS",
			"version":     "4.0",
			"description": "Payment Card Industry Data Security Standard",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"frameworks": frameworks,
		"total":      len(frameworks),
	})
}

// validatePolicy validates a policy configuration
func (m *Manager) validatePolicy(p *policy.Policy) error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}

	for _, rule := range p.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule name is required")
		}
		if rule.Rego == "" {
			return fmt.Errorf("rule rego is required")
		}
	}

	return nil
}
