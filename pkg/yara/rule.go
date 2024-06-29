package yara

import (
	"fmt"
)

// Rule represents a generic rule for Yara.
type Rule struct {
	ID          string
	Description string
	Pattern     string
}

// ConvertToYara converts a generic rule to a Yara rule.
func (r *Rule) ConvertToYara() string {
	return fmt.Sprintf(`rule GenericRule {
meta:
    id = "%s"
    description = "%s"
strings:
    $pattern = "%s"
condition:
    $pattern
}`, r.ID, r.Description, r.Pattern)
}
