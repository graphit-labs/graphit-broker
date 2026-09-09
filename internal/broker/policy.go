package broker

import (
	"strings"
	"time"
)

// PolicyDocument is the versioned resource-grant snapshot returned by the control store.
// Resource grants remain independent from system-wide RBAC roles.
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
