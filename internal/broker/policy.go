package broker

import (
	"strings"
	"time"
)

// PolicyDocument is the versioned resource-grant snapshot returned by the control store.
// Administrative roles are deliberately stored and managed separately.
type PolicyDocument struct {
	Version   int             `json:"v"`
	Revision  uint64          `json:"revision"`
	UpdatedAt time.Time       `json:"updated_at"`
	Rules     []ACLRuleConfig `json:"rules"`
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
