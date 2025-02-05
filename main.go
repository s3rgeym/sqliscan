package main

import (
	"encoding/json"
	"io"
	"os"
	"sqliscan/config"
	"sqliscan/logger"
	"sqliscan/scanner"
	"sqliscan/utils"
)

func main() {
	cfg := config.ParseFlags()

	logger.SetupLogger(cfg.LogLevel)

	var reader io.Reader
	if cfg.InputFile != "" {
		file, err := os.Open(cfg.InputFile)
		if err != nil {
			logger.Fatalf("Failed to open input file: %v", err)
		}
		defer file.Close()
		reader = file
	} else {
		reader = os.Stdin
	}

	urls, err := utils.ReadURLs(reader)
	if err != nil {
		logger.Fatalf("Failed to read URLs: %v", err)
	}

	var outputFile *os.File
	if cfg.OutputFile != "" {
		file, err := os.Create(cfg.OutputFile)
		if err != nil {
			logger.Fatalf("Failed to create output file: %v", err)
		}
		defer file.Close()
		outputFile = file
	} else {
		outputFile = os.Stdout
	}

	scan := scanner.NewScanner(
		scanner.WithConcurrencyLimit(cfg.ConcurrencyLimit),
		scanner.WithCrawlDepth(cfg.CrawlDepth),
		scanner.WithMaxCheckParams(cfg.MaxCheckParams),
		scanner.WithMaxHostErrors(cfg.MaxHostErrors),
		scanner.WithMaxInternalLinks(cfg.MaxInternalLinks),
		scanner.WithMaxRetries(cfg.MaxRetries),
		scanner.WithProxyURL(cfg.ProxyURL),
		scanner.WithRateLimit(cfg.RateLimitInterval),
		scanner.WithSkipCMSCheck(cfg.SkipCMSCheck),
		scanner.WithSkipVerify(cfg.SkipVerify),
		scanner.WithTimeout(cfg.Timeout),
		scanner.WithUserAgent(cfg.UserAgent),
	)

	results := scan.Scan(urls)

	for result := range results {
		js, err := json.Marshal(result)
		if err != nil {
			logger.Errorf("Failed to marshal result: %v", err)
			continue
		}
		outputFile.Write(js)
		outputFile.Write([]byte{'\n'})
	}
}
