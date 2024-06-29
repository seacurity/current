package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/seacurity/current/internal/sources/abuse_ch/malwarebazaar"
	"github.com/seacurity/current/internal/sources/ja4"
)

func main() {
	filePath := flag.String("file", "", "Path to the JA4 rules JSON file or MalwareBazaar API URL")
	sourceType := flag.String("source", "ja4", "Source type: ja4 or malwarebazaar")
	flag.Parse()

	if *filePath == "" {
		log.Fatal("File path or API URL is required")
	}

	// Ensure the /rules directory exists
	rulesDir := "rules/sigma"
	err := os.MkdirAll(rulesDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating rules directory: %v", err)
	}

	switch *sourceType {
	case "ja4":
		rules, err := ja4.LoadRulesFromFile(*filePath)
		if err != nil {
			log.Fatalf("Error loading JA4 rules: %v", err)
		}

		sigmaRules, err := ja4.ConvertRulesToSigma(rules)
		if err != nil {
			log.Fatalf("Error converting rules: %v", err)
		}

		for i, sigmaRule := range sigmaRules {
			ruleFilePath := filepath.Join(rulesDir, fmt.Sprintf("rule_ja4_%d.yml", i+1))
			err := os.WriteFile(ruleFilePath, []byte(sigmaRule), 0644)
			if err != nil {
				log.Fatalf("Error writing rule to file: %v", err)
			}
			fmt.Printf("Converted rule saved to: %s\n", ruleFilePath)
		}

	case "malwarebazaar":
		samples, err := malwarebazaar.FetchSamples(*filePath)
		if err != nil {
			log.Fatalf("Error fetching MalwareBazaar samples: %v", err)
		}

		sigmaRules, err := malwarebazaar.ConvertSamplesToSigma(samples)
		if err != nil {
			log.Fatalf("Error converting samples: %v", err)
		}

		for i, sigmaRule := range sigmaRules {
			ruleFilePath := filepath.Join(rulesDir, fmt.Sprintf("rule_malwarebazaar_%d.yml", i+1))
			err := os.WriteFile(ruleFilePath, []byte(sigmaRule), 0644)
			if err != nil {
				log.Fatalf("Error writing rule to file: %v", err)
			}
			fmt.Printf("Converted rule saved to: %s\n", ruleFilePath)
		}

	default:
		log.Fatalf("Unsupported source type: %s", *sourceType)
	}
}
