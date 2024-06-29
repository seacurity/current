package suricata

import (
	"fmt"
)

// Rule represents a generic rule for Suricata.
type Rule struct {
	ID          string
	Description string
	Pattern     string
}

// ConvertToSuricata converts a generic rule to a Suricata rule.
func (r *Rule) ConvertToSuricata() string {
	return fmt.Sprintf(`alert tcp any any -> any any (msg:"Generic Rule Alert"; content:"%s"; sid:%s; rev:1;)`, r.Pattern, r.ID)
}
