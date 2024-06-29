package malwarebazaar

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
)

// FetchSamples fetches malware samples from MalwareBazaar.
func FetchSamples(apiURL string) ([]*Sample, error) {
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch samples: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result struct {
		Samples []*Sample `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Initialize each sample with a UUID
	for _, sample := range result.Samples {
		sample.SigmaUUID = uuid.New().String()
	}

	return result.Samples, nil
}

// ConvertSamplesToSigma converts multiple MalwareBazaar samples to Sigma rules.
func ConvertSamplesToSigma(samples []*Sample) ([]string, error) {
	var sigmaRules []string
	for _, sample := range samples {
		sigmaRule, err := ConvertSampleToSigma(sample)
		if err != nil {
			return nil, err
		}
		sigmaRules = append(sigmaRules, sigmaRule)
	}
	return sigmaRules, nil
}

// ConvertSampleToSigma converts a MalwareBazaar sample to a Sigma rule.
func ConvertSampleToSigma(sample *Sample) (string, error) {
	if sample == nil {
		return "", fmt.Errorf("sample is nil")
	}
	return sample.ConvertToSigma(), nil
}
