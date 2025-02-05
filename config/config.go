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
	MaxCheckParams    int
	MaxHostErrors     int
	MaxInternalLinks  int
	MaxRetries        int
	ProxyURL          string
	RateLimitInterval time.Duration
	SkipCMSCheck      bool
	SkipVerify        bool
	Timeout           time.Duration
	UserAgent         string
}

func registerFlags(cfg *Config) {
	flag.BoolVar(&cfg.SkipCMSCheck, "skip-cms-check", false, "Skip CMS check")
	flag.BoolVar(&cfg.SkipVerify, "skip-verify", false, "Disable SSL certificate validation")
	flag.DurationVar(&cfg.RateLimitInterval, "r", 50*time.Millisecond, "Delay between requests")
	flag.DurationVar(&cfg.Timeout, "t", 15*time.Second, "Request timeout duration")
	flag.IntVar(&cfg.ConcurrencyLimit, "c", 10, "Number of concurrent requests")
	flag.IntVar(&cfg.CrawlDepth, "depth", 3, "Maximum link depth for crawling")
	flag.IntVar(&cfg.MaxCheckParams, "check-params", 10, "Maximum number of check parameters")
	flag.IntVar(&cfg.MaxHostErrors, "host-errors", 30, "Max allowed errors per host")
	flag.IntVar(&cfg.MaxInternalLinks, "internal-links", 150, "Max number of internal links to follow")
	flag.IntVar(&cfg.MaxRetries, "retries", 3, "Retry attempts per request")
	flag.StringVar(&cfg.InputFile, "i", "", "Path to input file with URLs")
	flag.StringVar(&cfg.LogLevel, "log", "info", "Logging level: debug, info, warn, error")
	flag.StringVar(&cfg.OutputFile, "o", "", "Path to output file for results")
	flag.StringVar(&cfg.ProxyURL, "proxy", "", "Proxy URL for requests")
	flag.StringVar(&cfg.UserAgent, "ua", "", "Custom User-Agent header")
}

func ParseFlags() Config {
	var cfg Config
	registerFlags(&cfg)
	flag.Parse()
	return cfg
}
