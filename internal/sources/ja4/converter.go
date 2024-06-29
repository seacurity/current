package ja4

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/uuid"
)

// LoadRulesFromFile loads multiple JA4 rules from a JSON file.
func LoadRulesFromFile(filePath string) ([]*Rule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Initialize each rule with a UUID
	for _, rule := range rules {
		rule.SigmaUUID = uuid.New().String()
	}

	return rules, nil
}

// ConvertRulesToSigma converts multiple JA4 rules to Sigma rules.
func ConvertRulesToSigma(rules []*Rule) ([]string, error) {
	var sigmaRules []string
	for _, rule := range rules {
		sigmaRule, err := ConvertRuleToSigma(rule)
		if err != nil {
			return nil, err
		}
		sigmaRules = append(sigmaRules, sigmaRule)
	}
	return sigmaRules, nil
}

// ConvertRuleToSigma converts a JA4 rule to a Sigma rule.
func ConvertRuleToSigma(rule *Rule) (string, error) {
	if rule == nil {
		return "", fmt.Errorf("rule is nil")
	}
	return rule.ConvertToSigma(), nil
}
