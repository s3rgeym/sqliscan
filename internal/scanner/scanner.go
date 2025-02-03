package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sqliscan/internal/logger"
	"sqliscan/internal/utils"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/time/rate"
)

var (
	quotes          = "\"'"
	sqlErrorPattern = regexp.MustCompile(`SQL syntax.*MySQL|Unclosed quotation mark.*SQL Server|You have an error in your SQL syntax|Warning.*pg_query|SQLite.*near|syntax error`)
)

type Scanner struct {
	checked          sync.Map
	client           *retryablehttp.Client
	concurrencyLimit int
	crawlDepth       int
	hostErrors       map[string]int
	hostVisits       map[string]int
	lim              *rate.Limiter
	maxHostErrors    int
	maxInternalLinks int
	mu               sync.Mutex
	semaphore        chan struct{}
	useCMSCheck      bool
	userAgent        string
	visited          sync.Map
	wg               sync.WaitGroup
}

type Option func(*Scanner)

type SQLiCheck struct {
	Method string            `json:"method"`
	URL    string            `json:"url"`
	Params map[string]string `json:"params"`
}

type SQLiDetails struct {
	ErrorMessage string `json:"error_message"`
	PageTitle    string `json:"page_title"`
	StatusCode   int    `json:"status_code"`
	VulnParam    string `json:"vuln_param"`
}

type ScanResult struct {
	SQLiCheck
	SQLiDetails
	ResultAt string `json:"result_at"`
}

func NewScanner(opts ...Option) *Scanner {
	transport := &http.Transport{}
	client := retryablehttp.NewClient()

	// Отключаем логирование
	client.Logger = nil

	client.HTTPClient.Transport = transport

	// Отключаем redirect
	client.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	s := &Scanner{
		client:           client,
		concurrencyLimit: 20,
		crawlDepth:       3,
		hostVisits:       make(map[string]int),
		lim:              rate.NewLimiter(rate.Every(50*time.Millisecond), 1),
		maxHostErrors:    50,
		maxInternalLinks: 150,
		useCMSCheck:      true,
		userAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}
	for _, opt := range opts {
		opt(s)
	}
	s.semaphore = make(chan struct{}, s.concurrencyLimit)
	return s
}

func WithConcurrencyLimit(limit int) Option {
	return func(s *Scanner) {
		s.concurrencyLimit = limit
	}
}

func WithRateLimit(interval time.Duration) Option {
	return func(s *Scanner) {
		s.lim = rate.NewLimiter(rate.Every(interval), 1)
	}
}

func WithMaxRetries(retries int) Option {
	return func(s *Scanner) {
		s.client.RetryMax = retries
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		s.client.HTTPClient.Timeout = timeout
	}
}

func WithSkipVerify(skipVerify bool) Option {
	return func(s *Scanner) {
		transport := s.client.HTTPClient.Transport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: skipVerify}
	}
}

func WithCrawlDepth(depth int) Option {
	return func(s *Scanner) {
		s.crawlDepth = depth
	}
}

func WithMaxInternalLinks(limit int) Option {
	return func(s *Scanner) {
		s.maxInternalLinks = limit
	}
}

func WithMaxHostErrors(limit int) Option {
	return func(s *Scanner) {
		s.maxHostErrors = limit
	}
}

func WithUserAgent(userAgent string) Option {
	return func(s *Scanner) {
		if userAgent != "" {
			s.userAgent = userAgent
		}
	}
}

func WithProxyURL(proxyAddr string) Option {
	return func(s *Scanner) {
		if proxyAddr != "" {
			parsed, err := url.Parse(proxyAddr)
			if err != nil {
				logger.Fatalf("Invalid proxy address: %v", err)
			}
			transport := s.client.HTTPClient.Transport.(*http.Transport)
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
}

func WithSkipCMSCheck(check bool) Option {
	return func(s *Scanner) {
		s.useCMSCheck = !check
	}
}

func (s *Scanner) performRequest(method, target string, params map[string]string) (*http.Response, error) {
	if err := s.lim.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error: %v", err)
		return nil, err
	}
	method = strings.ToUpper(method)
	req, err := retryablehttp.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}
	s.setHeaders(req)
	if method == http.MethodGet || method == http.MethodHead {
		q := req.URL.Query()
		for key, value := range params {
			q.Add(key, value)
		}
		req.URL.RawQuery = q.Encode()
	} else {
		form := url.Values{}
		for key, value := range params {
			form.Add(key, value)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	}
	return s.client.Do(req)
}

func (s *Scanner) isHostErrorLimit(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	errors, exists := s.hostErrors[host]
	if !exists {
		return false
	}
	return errors >= s.maxHostErrors
}

func (s *Scanner) increaseHostErrors(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostErrors[host]++
}

func (s *Scanner) sendRequest(method, url string, params map[string]string) ([]byte, int, http.Header, error) {
	host := utils.ExtractHost(url)
	if s.isHostErrorLimit(host) {
		return nil, 0, nil, fmt.Errorf("host error limit exceeded")
	}
	resp, err := s.performRequest(method, url, params)
	if err != nil {
		s.increaseHostErrors(host)
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, nil, err
	}
	logger.Debugf("%d - %s %s", resp.StatusCode, method, url)
	return body, resp.StatusCode, resp.Header, nil
}

func (s *Scanner) isCMS(body string) bool {
	indicators := []string{
		"/wp-content/", // Wordpress
		"Joomla! - Open Source Content Management", // Joomla
		"/sites/all/modules/",                      // Drupal
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}

func (s *Scanner) crawl(url string, depth int, sqliChecks chan<- SQLiCheck) {
	defer s.wg.Done() // у нас рекурсия!!!
	if s.isLimitReached(url) {
		logger.Debugf("Skip %s: limit reached", url)
		<-s.semaphore
		return
	}

	body, status, header, err := s.sendRequest(http.MethodGet, url, nil)
	<-s.semaphore

	if err != nil {
		logger.Errorf("Request failed: %s (%v)", url, err)
		return
	}

	s.setVisited(url)
	if status != http.StatusOK {
		logger.Debugf("Skip %s with status %d", url, status)
		return
	}

	mediaType, _ := utils.GetMediaType(header)
	if mediaType != "text/html" {
		logger.Errorf("Non-HTML response: %s", url)
		return
	}

	if s.useCMSCheck && s.isCMS(string(body)) {
		logger.Warnf("CMS detected: %s", url)
		return
	}

	s.extractLinks(body, url, depth, sqliChecks)
	s.extractForms(body, url, sqliChecks)
}

func (s *Scanner) extractLinks(body []byte, baseURL string, depth int, sqliChecks chan<- SQLiCheck) {
	links, _ := utils.ExtractLinks(body, baseURL)
	for _, link := range links {
		link, err := utils.StripFragment(link)
		if err != nil || !utils.IsSameHost(link, baseURL) || s.isIgnoredResource(link) || s.isVisited(link) {
			continue
		}

		if depth > 0 {
			s.wg.Add(1)
			s.semaphore <- struct{}{}
			go s.crawl(link, depth-1, sqliChecks)
		}

		checkURL, checkParams, _ := utils.SplitURLParams(link)
		logger.Debugf("Split URL params: %s, %v", checkURL, checkParams)

		if len(checkParams) == 0 {
			checkURL = s.injectSQLiPayload(checkURL)
		}

		sqliChecks <- SQLiCheck{Method: http.MethodGet, URL: checkURL, Params: checkParams}
	}
}

func (s *Scanner) autoFillFields(fields map[string]string) map[string]string {
	filledFields := make(map[string]string)

	defaultValues := map[string]string{
		"email":    "dummy@gmail.com",
		"password": "P@ssw0rd123",
		"username": "dummy",
		"phone":    "+1234567890",
		"address":  "123 Main St",
		"id":       "123",
		"":         "foo",
	}

	for key, value := range fields {
		if value == "" {
			for k, v := range defaultValues {
				if strings.Contains(strings.ToLower(key), k) {
					filledFields[key] = v
					break
				}
			}
		} else {
			filledFields[key] = value
		}
	}

	return filledFields
}

func (s *Scanner) extractForms(body []byte, baseURL string, sqliChecks chan<- SQLiCheck) {
	forms, _ := utils.ExtractForms(body, baseURL)
	for _, form := range forms {
		// Пропускаем формы, ведущие на сторонние домены
		if !utils.IsSameHost(form.Action, baseURL) {
			continue
		}
		logger.Debugf("Form found: Method=%s, Action=%s, Fields=%v", form.Method, form.Action, form.Fields)
		sqliChecks <- SQLiCheck{Method: form.Method, URL: form.Action, Params: s.autoFillFields(form.Fields)}
	}
}

func (s *Scanner) injectSQLiPayload(target string) string {
	payload := url.QueryEscape(quotes)
	if strings.Count(target, "/") > 3 && strings.HasSuffix(target, "/") {
		return target[:len(target)-1] + payload + "/"
	}
	return target + payload
}

func (s *Scanner) generateCheckKey(check SQLiCheck) (string, error) {
	u, err := url.Parse(check.URL)
	if err != nil {
		return "", err
	}

	query := u.Query()
	for key := range check.Params {
		query.Add(key, "") // Добавляем ключ без значения
	}
	u.RawQuery = query.Encode()

	// Формируем итоговый URL
	u.RawQuery = strings.ReplaceAll(u.RawQuery, "=", "")
	return fmt.Sprintf("%s %s", check.Method, u.String()), nil
}

func (s *Scanner) checkSQLi(check SQLiCheck, results chan<- ScanResult) {
	defer func() {
		<-s.semaphore
		s.wg.Done()
	}()

	checkKey, err := s.generateCheckKey(check)
	if err != nil {
		logger.Errorf("Generate check key error: %v", err)
		return
	}

	if _, loaded := s.checked.LoadOrStore(checkKey, struct{}{}); loaded {
		logger.Debugf("Skip checked: %s", checkKey)
		return
	}

	detected, details := s.detectSQLi(check)
	if !detected {
		return
	}

	results <- ScanResult{
		SQLiCheck:   check,
		SQLiDetails: details,
		ResultAt:    time.Now().Local().String(),
	}
}

func (s *Scanner) detectSQLi(check SQLiCheck) (bool, SQLiDetails) {
	if len(check.Params) == 0 {
		logger.Debugf("Check SQLi: %s %s", check.Method, check.URL)
		body, _, _, _ := s.sendRequest(check.Method, check.URL, nil)
		htmlContent := string(body)
		match := sqlErrorPattern.FindString(htmlContent)
		if match == "" {
			return false, SQLiDetails{}
		}
		title := utils.ExtractTitle(htmlContent)
		return true, SQLiDetails{ErrorMessage: match, PageTitle: title}
	}

	count := 5
	for param := range check.Params {
		// Проверяем только 5 первых параметров
		if count >= 5 {
			break
		}
		params := utils.CopyStringMap(check.Params)
		params[param] += quotes
		logger.Debugf("Check SQLi: %s %s; param=%q", check.Method, check.URL, param)
		body, _, _, _ := s.sendRequest(check.Method, check.URL, params)
		htmlContent := string(body)
		if match := sqlErrorPattern.FindString(htmlContent); match != "" {
			title := utils.ExtractTitle(htmlContent)
			return true, SQLiDetails{ErrorMessage: match, VulnParam: param, PageTitle: title}
		}
		count++
	}
	return false, SQLiDetails{}
}

func (s *Scanner) Scan(urls []string) <-chan ScanResult {
	logger.Debugf("Scanning %d URLs", len(urls))
	logger.Debugf("CMS Check: %v", s.useCMSCheck)
	sqliChecks := make(chan SQLiCheck)
	results := make(chan ScanResult)
	go func() {
		defer func() {
			close(sqliChecks)
			close(results)
		}()
		go func() {
			for check := range sqliChecks {
				s.wg.Add(1)
				s.semaphore <- struct{}{}
				go s.checkSQLi(check, results)
			}
		}()
		for _, url := range urls {
			s.wg.Add(1)
			s.semaphore <- struct{}{}
			go s.crawl(url, s.crawlDepth, sqliChecks)
		}
		s.wg.Wait()
	}()
	return results
}

func (s *Scanner) setHeaders(req *retryablehttp.Request) {
	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.8",
		"User-Agent":      s.userAgent,
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func (s *Scanner) isLimitReached(url string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	host := utils.ExtractHost(url)
	//logger.Debugf("Requests for %s %s: %d", url, host, s.hostVisits[host])
	s.hostVisits[host]++
	return s.hostVisits[host] > s.maxInternalLinks
}

func (s *Scanner) setVisited(url string) {
	s.visited.Store(url, struct{}{})
}

func (s *Scanner) isVisited(url string) bool {
	_, ok := s.visited.Load(url)
	return ok
}

var ignoredExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".bmp",
	".pdf", ".doc", ".docx", ".xls", ".xlsx",
	".zip", ".rar", ".tar", ".gz", ".mp3",
	".mp4", ".avi", ".mov", ".exe", ".dmg",
}

func (s *Scanner) isIgnoredResource(inputURL string) bool {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, ext := range ignoredExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
