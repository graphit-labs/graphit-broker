package broker

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrPolicyConflict = errors.New("access policy revision conflict")

type PolicyDocument struct {
	Version   int             `json:"v"`
	Revision  uint64          `json:"revision"`
	UpdatedAt time.Time       `json:"updated_at"`
	Rules     []ACLRuleConfig `json:"rules"`
}

type PolicyStore struct {
	mu             sync.RWMutex
	revisionPrefix string
	storage        S3ServiceConfig
	document       PolicyDocument
}

// PolicyStore is the immutable runtime view used by ACL evaluation. Durable persistence belongs
// to ControlStore, which swaps an entirely rebuilt runtime after a validated SQLite transaction.
func NewPolicyStore(initial AuthorizationConfig, revisionPrefix string, storage ...S3ServiceConfig) (*PolicyStore, error) {
	store := &PolicyStore{revisionPrefix: strings.TrimSpace(revisionPrefix)}
	if len(storage) > 0 {
		store.storage = storage[0]
	}
	if store.revisionPrefix == "" {
		store.revisionPrefix = "acl"
	}
	seed := PolicyDocument{Version: 1, Revision: 1, UpdatedAt: time.Now().UTC(), Rules: cloneRules(initial.Rules)}
	if err := store.validateRules(seed.Rules); err != nil {
		return nil, err
	}
	store.document = seed
	return store, nil
}

func (s *PolicyStore) Snapshot() PolicyDocument {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clonePolicy(s.document)
}

func (s *PolicyStore) Revision() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revisionPrefix + "." + strconv.FormatUint(s.document.Revision, 10)
}

func (s *PolicyStore) Replace(expected uint64, rules []ACLRuleConfig) (PolicyDocument, error) {
	if err := s.validateRules(rules); err != nil {
		return PolicyDocument{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.document.Revision {
		return PolicyDocument{}, ErrPolicyConflict
	}
	next := PolicyDocument{Version: 1, Revision: s.document.Revision + 1, UpdatedAt: time.Now().UTC(), Rules: cloneRules(rules)}
	s.document = next
	return clonePolicy(next), nil
}

func (s *PolicyStore) validateRules(rules []ACLRuleConfig) error {
	for i, rule := range rules {
		if err := validateACLRule(rule); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if !s.storage.Enabled || !ruleUsesS3(rule) {
			continue
		}
		routeName := strings.TrimSpace(rule.S3Route)
		if routeName == "" {
			routeName = s.storage.DefaultRoute
		}
		_, exists := s.storage.Routes[routeName]
		if !exists {
			return fmt.Errorf("rule %d: storage route %q is not configured", i, routeName)
		}
	}
	return nil
}

func ruleUsesS3(rule ACLRuleConfig) bool {
	for _, capability := range rule.Capabilities {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if capability == "s3" || strings.HasPrefix(capability, "s3:") {
			return true
		}
	}
	return false
}

func clonePolicy(document PolicyDocument) PolicyDocument {
	document.Rules = cloneRules(document.Rules)
	return document
}

func cloneRules(rules []ACLRuleConfig) []ACLRuleConfig {
	out := make([]ACLRuleConfig, len(rules))
	for i, rule := range rules {
		out[i] = rule
		out[i].Capabilities = append([]string(nil), rule.Capabilities...)
		out[i].Projects = append([]string(nil), rule.Projects...)
		out[i].S3Operations = append([]string(nil), rule.S3Operations...)
		out[i].S3Prefixes = append([]string(nil), rule.S3Prefixes...)
	}
	return out
}
