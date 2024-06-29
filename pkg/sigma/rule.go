package sigma

import (
	"fmt"
)

// Rule represents a generic rule for Sigma.
type Rule struct {
	ID          string
	Description string
	Pattern     string
}

// ConvertToSigma converts a generic rule to a Sigma rule.
func (r *Rule) ConvertToSigma() string {
	return fmt.Sprintf(`title: Generic Rule to Sigma
id: %s
description: %s
logsource:
    category: generic
detection:
    selection:
        pattern: '%s'
    condition: selection
falsepositives:
    - Unknown
level: medium`, r.ID, r.Description, r.Pattern)
}
