package config

import (
	"flag"
	"time"
)

type Config struct {
	InputFile         string
	OutputFile        string
	ConcurrencyLimit  int
	CrawlDepth        int
	LogLevel          string
	MaxHostErrors     int
	MaxInternalLinks  int
	MaxRetries        int
	ProxyURL          string
	RateLimitInterval time.Duration
	SkipVerify        bool
	Timeout           time.Duration
	SkipCMSCheck      bool
	UserAgent         string
}

func ParseFlags() Config {
	var cfg Config

	flag.BoolVar(&cfg.SkipCMSCheck, "skip-cms-check", false, "Skip CMS Check")
	flag.BoolVar(&cfg.SkipVerify, "skip-verify", false, "Skip SSL certificate verification")
	flag.DurationVar(&cfg.RateLimitInterval, "r", 50*time.Millisecond, "Rate limit interval between requests")
	flag.DurationVar(&cfg.Timeout, "t", 15*time.Second, "Request timeout")
	flag.IntVar(&cfg.ConcurrencyLimit, "c", 20, "Concurrency limit")
	flag.IntVar(&cfg.CrawlDepth, "depth", 3, "Crawl depth")
	flag.IntVar(&cfg.MaxHostErrors, "host-errors", 50, "Maximum errors allowed per host")
	flag.IntVar(&cfg.MaxInternalLinks, "internal-links", 150, "Maximum number of internal links")
	flag.IntVar(&cfg.MaxRetries, "retries", 3, "Maximum number of retries for each request")
	flag.StringVar(&cfg.InputFile, "i", "", "Input file with list of URLs")
	flag.StringVar(&cfg.LogLevel, "log", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file for results")
	flag.StringVar(&cfg.ProxyURL, "proxy", "", "Proxy URL for requests")
	flag.StringVar(&cfg.UserAgent, "ua", "", "Custom User-Agent")

	flag.Parse()

	return cfg
}
