package virustotal

import (
	"fmt"
)

// Rule represents a VirusTotal rule.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
}

// ConvertToSigma converts a VirusTotal rule to a Sigma rule.
func (r *Rule) ConvertToSigma() string {
	return fmt.Sprintf(`title: VirusTotal Rule to Sigma
id: %s
description: %s
logsource:
    category: network
    product: virustotal
detection:
    selection:
        pattern: '%s'
    condition: selection
falsepositives:
    - Unknown
level: medium`, r.ID, r.Description, r.Pattern)
}
