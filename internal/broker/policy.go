package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	path           string
	revisionPrefix string
	storage        S3ServiceConfig
	document       PolicyDocument
}

func NewPolicyStore(cfg AdministrationConfig, initial AuthorizationConfig, revisionPrefix string, storage ...S3ServiceConfig) (*PolicyStore, error) {
	store := &PolicyStore{path: strings.TrimSpace(cfg.StateFile), revisionPrefix: strings.TrimSpace(revisionPrefix)}
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
	if store.path == "" {
		store.document = seed
		return store, nil
	}
	document, err := loadPolicyDocument(store.path)
	if err == nil {
		if err := store.validateRules(document.Rules); err != nil {
			return nil, fmt.Errorf("validate access policy %s: %w", store.path, err)
		}
		store.document = document
		return store, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	store.document = seed
	if err := store.persistLocked(seed); err != nil {
		return nil, err
	}
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
	if s.path == "" {
		return s.revisionPrefix
	}
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
	if s.path != "" {
		if err := s.persistLocked(next); err != nil {
			return PolicyDocument{}, err
		}
	}
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

func loadPolicyDocument(path string) (PolicyDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return PolicyDocument{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var document PolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return PolicyDocument{}, fmt.Errorf("decode access policy %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return PolicyDocument{}, fmt.Errorf("decode access policy %s: trailing JSON", path)
	}
	if document.Version != 1 || document.Revision == 0 {
		return PolicyDocument{}, fmt.Errorf("access policy %s needs v=1 and a positive revision", path)
	}
	for i, rule := range document.Rules {
		if err := validateACLRule(rule); err != nil {
			return PolicyDocument{}, fmt.Errorf("access policy %s rule %d: %w", path, i, err)
		}
	}
	document.Rules = cloneRules(document.Rules)
	return document, nil
}

func (s *PolicyStore) persistLocked(document PolicyDocument) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create access policy directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure access policy directory: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".access-policy-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary access policy: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary access policy: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode access policy: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync access policy: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close access policy: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace access policy: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("secure access policy: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func clonePolicy(document PolicyDocument) PolicyDocument {
	document.Rules = cloneRules(document.Rules)
	return document
}

func cloneRules(rules []ACLRuleConfig) []ACLRuleConfig {
	out := make([]ACLRuleConfig, len(rules))
	for i, rule := range rules {
		out[i] = rule
		out[i].Subjects = append([]string(nil), rule.Subjects...)
		out[i].Users = append([]string(nil), rule.Users...)
		out[i].Organizations = append([]string(nil), rule.Organizations...)
		out[i].Teams = append([]string(nil), rule.Teams...)
		out[i].Capabilities = append([]string(nil), rule.Capabilities...)
		out[i].Projects = append([]string(nil), rule.Projects...)
		out[i].S3Operations = append([]string(nil), rule.S3Operations...)
		out[i].S3Prefixes = append([]string(nil), rule.S3Prefixes...)
	}
	return out
}
