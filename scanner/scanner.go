package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sqliscan/cloudflare_challenge_parser"
	"sqliscan/logger"
	"sqliscan/utils"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/time/rate"
)

var (
	// null-байт служит индикатором конца строки в C/C++
	//sqliPayload     = "'\"\x00"
	sqliPayload = "'\""

	// Тут только ошибки, которые возникают при неожиданной кавычке
	sqlErrorPattern = regexp.MustCompile(`You have an error in your SQL syntax|Unclosed quote at position|<b>(?:Fatal error|Warning)</b>:|:[^:]*syntax error|Unterminated quoted string at or near|Unclosed quotation mark after the character string|quoted string not properly terminated|Incorrect syntax near|could not execute query|bad SQL grammar`)
)

type Scanner struct {
	checked          sync.Map
	client           *retryablehttp.Client
	concurrencyLimit int
	crawlDepth       int
	hostErrors       map[string]int
	hostVisits       map[string]int
	lim              *rate.Limiter
	maxCheckParams   int
	maxHostErrors    int
	maxInternalLinks int
	mu               sync.Mutex
	sem              chan struct{}
	skipCMSCheck     bool
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
	PageTitle    string `json:"title"`
	StatusCode   int    `json:"status_code"`
	VulnParam    string `json:"vuln_param"`
}

type ScanResult struct {
	SQLiCheck
	SQLiDetails
	ResultAt string `json:"result_at"`
}

func NewScanner(opts ...Option) *Scanner {
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{}
	client := retryablehttp.NewClient()

	// Отключаем логирование
	client.Logger = nil
	client.HTTPClient.Transport = transport
	client.HTTPClient.Jar = jar

	// Отключаем redirect
	client.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Этот фрагмент вроде не нужен, но на всякий случай
		if len(via) == 0 {
			return nil // Первый запрос, редиректов ещё не было
		}

		prevReq := via[len(via)-1] // Последний запрос перед редиректом

		if prevReq.URL.Host != req.URL.Host {
			return http.ErrUseLastResponse // Блокируем редирект на другой хост
		}

		return nil // Разрешаем редирект
	}

	scanner := &Scanner{
		client:           client,
		concurrencyLimit: 20,
		crawlDepth:       3,
		hostErrors:       make(map[string]int),
		hostVisits:       make(map[string]int),
		lim:              rate.NewLimiter(rate.Every(50*time.Millisecond), 1),
		maxCheckParams:   10,
		maxHostErrors:    50,
		maxInternalLinks: 150,
		skipCMSCheck:     false,
		userAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	}
	for _, opt := range opts {
		opt(scanner)
	}
	scanner.sem = make(chan struct{}, scanner.concurrencyLimit)
	return scanner
}

func WithConcurrencyLimit(limit int) Option {
	return func(self *Scanner) {
		self.concurrencyLimit = limit
	}
}

func WithRateLimit(interval time.Duration) Option {
	return func(self *Scanner) {
		self.lim = rate.NewLimiter(rate.Every(interval), 1)
	}
}

func WithMaxRetries(retries int) Option {
	return func(self *Scanner) {
		self.client.RetryMax = retries
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(self *Scanner) {
		self.client.HTTPClient.Timeout = timeout
	}
}

func WithSkipVerify(skipVerify bool) Option {
	return func(self *Scanner) {
		transport := self.client.HTTPClient.Transport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: skipVerify}
	}
}

func WithCrawlDepth(depth int) Option {
	return func(self *Scanner) {
		self.crawlDepth = depth
	}
}

func WithMaxCheckParams(limit int) Option {
	return func(self *Scanner) {
		self.maxCheckParams = limit
	}
}

func WithMaxInternalLinks(limit int) Option {
	return func(self *Scanner) {
		self.maxInternalLinks = limit
	}
}

func WithMaxHostErrors(limit int) Option {
	return func(self *Scanner) {
		self.maxHostErrors = limit
	}
}

func WithUserAgent(userAgent string) Option {
	return func(self *Scanner) {
		if userAgent != "" {
			self.userAgent = userAgent
		}
	}
}

func WithProxyURL(proxyAddr string) Option {
	return func(self *Scanner) {
		if proxyAddr != "" {
			parsed, err := url.Parse(proxyAddr)
			if err != nil {
				logger.Fatalf("Invalid proxy address: %v", err)
			}
			transport := self.client.HTTPClient.Transport.(*http.Transport)
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
}

func WithSkipCMSCheck(check bool) Option {
	return func(self *Scanner) {
		self.skipCMSCheck = check
	}
}

func (self *Scanner) performRequest(method, target string, params map[string]string) (*http.Response, error) {
	if err := self.lim.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error: %v", err)
		return nil, err
	}
	method = strings.ToUpper(method)
	req, err := retryablehttp.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}
	self.setHeaders(req)
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
	return self.client.Do(req)
}

func (self *Scanner) isHostErrorLimit(host string) bool {
	self.mu.Lock()
	defer self.mu.Unlock()
	errors, exists := self.hostErrors[host]
	if !exists {
		return false
	}
	return errors >= self.maxHostErrors
}

func (self *Scanner) increaseHostErrors(host string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.hostErrors[host]++
}

func (self *Scanner) sendRequest(method, url string, params map[string]string) ([]byte, int, http.Header, error) {
	host, err := utils.ExtractHost(url)
	if err != nil {
		return nil, 0, nil, err
	}
	if self.isHostErrorLimit(host) {
		return nil, 0, nil, fmt.Errorf("host error limit exceeded")
	}
	resp, err := self.performRequest(method, url, params)
	if err != nil {
		self.increaseHostErrors(host)
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, nil, err
	}

	if bytes.Contains(body, []byte("<title>One moment, please...</title>")) {
		logger.Debugf("Cloudflare challenge detected: %s", url)

		challenge, err := cloudflare_challenge_parser.ParseCloudflareChallenge(string(body))
		if err != nil {
			return nil, 0, nil, err
		}
		actionURL, err := utils.URLJoin(url, challenge.Action)
		if err != nil {
			return nil, 0, nil, err
		}
		return self.sendRequest(challenge.Method, actionURL, map[string]string{
			"wsidchk": fmt.Sprintf("%d", challenge.Wsidchk),
		})
	}

	logger.Debugf("%d - %s %s", resp.StatusCode, method, url)
	return body, resp.StatusCode, resp.Header, nil
}

func (self *Scanner) detectCMS(body string) string {
	indicators := [][]string{
		{"Wordpress", "/wp-content/"},
		{"Joomla", "Joomla! - Open Source Content Management"},
		{"Drupal", "/sites/all/modules/"},
		{"Tilda", "https://static.tildacdn.com/"},
		// TODO: добавить еще
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator[1]) {
			return indicator[0]
		}
	}

	return ""
}

func (self *Scanner) crawl(url string, depth int, sqliChecks chan<- SQLiCheck) {
	defer self.wg.Done() // у нас рекурсия!!!
	if self.isLimitReached(url) {
		logger.Debugf("Skip %s: limit reached", url)
		<-self.sem
		return
	}

	body, status, header, err := self.sendRequest(http.MethodGet, url, nil)
	<-self.sem

	if err != nil {
		logger.Errorf("Request failed: %s (%v)", url, err)
		return
	}

	self.setVisited(url)
	if status != http.StatusOK {
		logger.Debugf("Skip %s with status %d", url, status)
		return
	}

	mediaType, _ := utils.GetMediaType(header)
	if mediaType != "text/html" {
		logger.Errorf("Non-HTML response: %s", url)
		return
	}

	if !self.skipCMSCheck {
		if cms := self.detectCMS(string(body)); cms != "" {
			logger.Warnf("CMS detected: %s - %s", url, cms)
			return
		}
	}

	self.processLinks(body, url, depth, sqliChecks)
	self.processForms(body, url, sqliChecks)
}

func (self *Scanner) processLinks(body []byte, baseURL string, depth int, sqliChecks chan<- SQLiCheck) {
	links, _ := utils.ExtractLinks(body, baseURL)
	for _, link := range links {
		link, err := utils.StripFragment(link)
		if err != nil || !utils.IsSameHost(link, baseURL) || self.isIgnoredResource(link) || self.isVisited(link) {
			continue
		}

		if depth > 0 {
			self.wg.Add(1)
			self.sem <- struct{}{}
			go self.crawl(link, depth-1, sqliChecks)
		}

		checkURL, checkParams, _ := utils.SplitURLParams(link)
		logger.Debugf("Split URL params: %s, %v", checkURL, checkParams)

		if len(checkParams) == 0 {
			checkURL = self.injectSQLiPayload(checkURL)
		}

		sqliChecks <- SQLiCheck{Method: http.MethodGet, URL: checkURL, Params: checkParams}
	}
}

func (self *Scanner) autoFillFields(fields map[string]string) map[string]string {
	defaultValues := map[string]string{
		"email":    "dummy@gmail.com",
		"password": "P@ssw0rd123",
		"username": "dummy",
		"phone":    "+1234567890",
		"address":  "123 Main St",
		"id":       "123",
	}

	getDefault := func(name, fallbackValue string) string {
		lowerName := strings.ToLower(name)
		for k, v := range defaultValues {
			if strings.Contains(lowerName, k) {
				return v
			}
		}
		return fallbackValue
	}

	filledFields := make(map[string]string)

	for key, value := range fields {
		if value == "" {
			filledFields[key] = getDefault(key, "foo")
		} else {
			filledFields[key] = value
		}
	}

	return filledFields
}

func (self *Scanner) processForms(body []byte, baseURL string, sqliChecks chan<- SQLiCheck) {
	forms, _ := utils.ExtractForms(body, baseURL)
	for _, form := range forms {
		// Пропускаем формы, ведущие на сторонние домены
		if !utils.IsSameHost(form.Action, baseURL) {
			continue
		}
		logger.Debugf("Form found: Method=%s, Action=%s, Fields=%v", form.Method, form.Action, form.Fields)
		sqliChecks <- SQLiCheck{Method: form.Method, URL: form.Action, Params: self.autoFillFields(form.Fields)}
	}
}

func (self *Scanner) injectSQLiPayload(target string) string {
	payload := url.QueryEscape(sqliPayload)
	if strings.Count(target, "/") > 3 && strings.HasSuffix(target, "/") {
		return target[:len(target)-1] + payload + "/"
	}
	return target + payload
}

func (self *Scanner) generateCheckKey(check SQLiCheck) (string, error) {
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

func (self *Scanner) checkSQLi(check SQLiCheck, results chan<- ScanResult) {
	defer func() {
		<-self.sem
		self.wg.Done()
	}()

	checkKey, err := self.generateCheckKey(check)
	if err != nil {
		logger.Errorf("Generate check key error: %v", err)
		return
	}

	if _, loaded := self.checked.LoadOrStore(checkKey, struct{}{}); loaded {
		logger.Debugf("Skip checked: %s", checkKey)
		return
	}

	detected, details := self.detectSQLi(check)
	if !detected {
		return
	}

	results <- ScanResult{
		SQLiCheck:   check,
		SQLiDetails: details,
		ResultAt:    time.Now().Local().String(),
	}
}

func (self *Scanner) detectSQLi(check SQLiCheck) (bool, SQLiDetails) {
	handle := func(params map[string]string) (string, int, string) {
		body, status, _, _ := self.sendRequest(check.Method, check.URL, params)
		htmlContent := string(body)
		errorMessage := sqlErrorPattern.FindString(htmlContent)
		if errorMessage == "" {
			return "", 0, ""
		}
		title := utils.ExtractTitle(htmlContent)
		return errorMessage, status, title
	}

	if len(check.Params) == 0 {
		logger.Debugf("Check SQLi: %s %s", check.Method, check.URL)
		errorMessage, status, title := handle(nil)
		if errorMessage != "" {
			return true, SQLiDetails{ErrorMessage: errorMessage, StatusCode: status, PageTitle: title}
		}
	} else {
		count := 0
		for param := range check.Params {
			if count >= self.maxCheckParams {
				break
			}
			params := utils.CopyStringMap(check.Params)
			params[param] += sqliPayload
			logger.Debugf("Check SQLi: %s %s; param=%q", check.Method, check.URL, param)
			errorMessage, status, title := handle(params)
			if errorMessage != "" {
				return true, SQLiDetails{ErrorMessage: errorMessage, VulnParam: param, PageTitle: title, StatusCode: status}
			}
			count++
		}
	}
	return false, SQLiDetails{}
}

func (self *Scanner) Scan(urls []string) <-chan ScanResult {
	logger.Debugf("Scanning %d URLs", len(urls))
	sqliChecks := make(chan SQLiCheck)
	results := make(chan ScanResult)
	go func() {
		defer func() {
			close(sqliChecks)
			close(results)
		}()
		go func() {
			for check := range sqliChecks {
				self.wg.Add(1)
				self.sem <- struct{}{}
				go self.checkSQLi(check, results)
			}
		}()
		for _, url := range urls {
			self.wg.Add(1)
			self.sem <- struct{}{}
			go self.crawl(url, self.crawlDepth, sqliChecks)
		}
		self.wg.Wait()
	}()
	return results
}

func (self *Scanner) setHeaders(req *retryablehttp.Request) {
	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.8",
		"User-Agent":      self.userAgent,
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func (self *Scanner) isLimitReached(url string) bool {
	self.mu.Lock()
	defer self.mu.Unlock()
	host, err := utils.ExtractHost(url)
	if err != nil {
		return false
	}
	//logger.Debugf("Requests for %s %s: %d", url, host, self.hostVisits[host])
	self.hostVisits[host]++
	return self.hostVisits[host] > self.maxInternalLinks
}

func (self *Scanner) setVisited(url string) {
	self.visited.Store(url, struct{}{})
}

func (self *Scanner) isVisited(url string) bool {
	_, ok := self.visited.Load(url)
	return ok
}

var ignoredExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".bmp",
	".pdf", ".doc", ".docx", ".xls", ".xlsx",
	".zip", ".rar", ".tar", ".gz", ".mp3",
	".mp4", ".avi", ".mov", ".exe", ".dmg",
}

func (self *Scanner) isIgnoredResource(inputURL string) bool {
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
