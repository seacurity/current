package misp

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// LoadRuleFromFile loads a MISP rule from a JSON file.
func LoadRuleFromFile(filePath string) (*Rule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var rule Rule
	if err := json.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &rule, nil
}

// ConvertRuleToSigma converts a MISP rule to a Sigma rule.
func ConvertRuleToSigma(rule *Rule) (string, error) {
	if rule == nil {
		return "", fmt.Errorf("rule is nil")
	}
	return rule.ConvertToSigma(), nil
}
