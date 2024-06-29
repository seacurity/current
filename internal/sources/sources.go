package sources

import (
	"errors"

	"github.com/seacurity/current/internal/sources/ja4"
)

// ConvertSourceRule converts a rule from any source to the specified format.
func ConvertSourceRule(source string, rule interface{}, format string) (string, error) {
	switch source {
	case "ja4":
		if format == "sigma" {
			return ja4.ConvertRuleToSigma(rule.(*ja4.Rule))
		}
		return "", errors.New("unsupported format for JA4 source")
	case "misp":
		// MISP conversion logic
	case "virustotal":
		// VirusTotal conversion logic
	default:
		return "", errors.New("unsupported source")
	}
	return "", errors.New("unsupported format")
}
