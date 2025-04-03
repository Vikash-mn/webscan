package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

func main() {
	target := os.Args[1]
	
	// Run all scans in parallel
	var wg sync.WaitGroup
	wg.Add(3)
	
	var subdomains []string
	var vulns []string
	var buckets []string
	
	go func() {
		defer wg.Done()
		subdomains = findSubdomains(target)
	}()
	
	go func() {
		defer wg.Done()
		vulns = scanVulnerabilities(target)
	}()
	
	go func() {
		defer wg.Done()
		buckets = findCloudBuckets(target)
	}()
	
	wg.Wait()
	
	report := map[string]interface{}{
		"subdomains":  subdomains,
		"vulnerabilities": vulns,
		"cloud_buckets": buckets,
	}
	
	jsonReport, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(jsonReport))
}

func findSubdomains(domain string) []string {
	options := runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}
	
	runner, err := runner.NewRunner(&options)
	if err != nil {
		log.Fatal(err)
	}
	
	return runner.Run(domain)
}

func scanVulnerabilities(target string) []string {
	engine := core.New(defaultOptions)
	templateRepo := templates.NewRepository()
	
	results := engine.Scan(target, templateRepo)
	var vulns []string
	for _, r := range results {
		vulns = append(vulns, r.TemplateID)
	}
	return vulns
}

func findCloudBuckets(domain string) []string {
	cmd := exec.Command("cloud_enum", "-k", domain)
	output, _ := cmd.CombinedOutput()
	
	var buckets []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "[+]") {
			buckets = append(buckets, line)
		}
	}
	return buckets
}