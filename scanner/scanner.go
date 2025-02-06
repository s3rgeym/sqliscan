package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sqliscan/cloudflare_jschallenge"
	"sqliscan/logger"
	"sqliscan/utils"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/time/rate"
)

const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	// Некоторые WAF блокируют идущие подряд запросы без Referer, поэтому мы передаем его всегда
	defaultReferer = "https://www.google.com/"
	quotes         = "'\""
	nullByte       = "\x00"
)

var (
	// Тут только ошибки, которые возникают при неожиданной кавычке в SQL
	sqlErrorPattern = regexp.MustCompile(`You have an error in your SQL syntax|syntax error at or near|Unclosed quote at position|Unterminated quoted string at or near|Unclosed quotation mark after the character string|quoted string not properly terminated|Incorrect syntax near|could not execute query|bad SQL grammar|<b>(?:Fatal error|Warning)</b>:`)
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

type ResponseWrapper struct {
	http.Response
	Body []byte
}

type SQLiCheck struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Params  map[string]string `json:"params,omitempty"`
	Referer string            `json:"referer,omitempty"`
}

type SQLiDetails struct {
	ErrorMessage string `json:"error_message,omitempty"`
	PageTitle    string `json:"title,omitempty"`
	StatusCode   int    `json:"status_code"`
	VulnParam    string `json:"vuln_param,omitempty"`
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
			return nil
		}

		prevReq := via[len(via)-1]

		if prevReq.URL.Host != req.URL.Host {
			return http.ErrUseLastResponse
		}

		return nil
	}

	s := &Scanner{
		client:           client,
		concurrencyLimit: 20,
		crawlDepth:       3,
		hostErrors:       make(map[string]int),
		hostVisits:       make(map[string]int),
		lim:              rate.NewLimiter(rate.Every(50*time.Millisecond), 1),
		maxCheckParams:   10,
		maxHostErrors:    30,
		maxInternalLinks: 150,
		skipCMSCheck:     false,
		userAgent:        defaultUserAgent,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.sem = make(chan struct{}, s.concurrencyLimit)
	return s
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

func (self *Scanner) hasBody(method string) bool {
	return method != http.MethodGet && method != http.MethodHead
}

func (self *Scanner) makeRequest(method, targetURL string, params map[string]string, referer string) (*ResponseWrapper, error) {
	host, err := utils.ExtractHost(targetURL)
	if err != nil {
		return nil, err
	}
	if self.isHostErrorLimit(host) {
		return nil, fmt.Errorf("host error limit exceeded")
	}
	method = strings.ToUpper(method)
	req, err := retryablehttp.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	if !self.hasBody(method) {
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
	if err := self.lim.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error: %v", err)
		self.increaseHostErrors(host)
		return nil, err
	}
	self.setHeaders(req, referer)
	resp, err := self.client.Do(req)
	if err != nil {
		self.increaseHostErrors(host)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		self.increaseHostErrors(host)
		return nil, err
	}
	logger.Debugf("%d - %s %s - %s", resp.StatusCode, method, targetURL, referer)
	return &ResponseWrapper{Body: body, Response: *resp}, nil
}

func (self *Scanner) isCloudflareChallenge(resp *ResponseWrapper) bool {
	return bytes.Contains(resp.Body, []byte("<title>One moment, please...</title>"))
}

func (self *Scanner) sendRequest(method, url string, params map[string]string, referer string) (*ResponseWrapper, error) {
	resp, err := self.makeRequest(method, url, params, referer)
	if err != nil {
		return nil, err
	}
	if self.isCloudflareChallenge(resp) {
		responseURL := resp.Request.URL.String()
		logger.Warnf("Cloudflare challenge detected: %s", responseURL)
		challenge, err := cloudflare_jschallenge.ParseChallenge(string(resp.Body))
		if err != nil {
			return nil, err
		}
		actionURL, err := utils.URLJoin(responseURL, challenge.Action)
		if err != nil {
			return nil, err
		}
		return self.makeRequest(challenge.Method, actionURL, map[string]string{
			"wsidchk": fmt.Sprintf("%d", challenge.Wsidchk),
		}, referer)
	}
	return resp, nil
}

func (self *Scanner) detectCMS(body string) string {
	indicators := [][]string{
		// https://stackcrawler.com/learn
		{"Wordpress", "/wp-content/"},
		// В meta generator
		{"Joomla", "Joomla! - Open Source Content Management"},
		{"Drupal", "/sites/all/modules/"},
		{"DLE", "DataLife Engine"},
		{"Bitrix", "/bitrix/templates/"},
		{"Shopify", "//cdn.shopify.com/"},
		// Название JS переменной
		{"Magento", "Mage.Cookies"},
		// В meta generator
		{"PrestaShop", "content=\"PrestaShop\""},
		// Далее пошли конструкторы
		{"Tilda", "//static.tildacdn.com/"},
		// В meta generator
		{"Wix", "Wix.com Website Builder"},
		// Им никто не пользуется все равно
		//{"Blogger", ".blogspot.com/"},
	}

	for _, indicator := range indicators {
		if strings.Contains(body, indicator[1]) {
			return indicator[0]
		}
	}

	return ""
}

func (self *Scanner) crawl(url string, depth int, referer string, sqliChecks chan<- SQLiCheck) {
	defer self.wg.Done() // у нас рекурсия!!!
	if self.isLimitReached(url) {
		logger.Debugf("Skip %s: limit reached", url)
		<-self.sem
		return
	}

	resp, err := self.sendRequest(http.MethodGet, url, nil, referer)
	<-self.sem

	if err != nil {
		logger.Errorf("Request failed: %s (%v)", url, err)
		return
	}

	self.setVisited(url)
	currentURL := resp.Request.URL.String()
	self.setVisited(currentURL)

	if resp.StatusCode != http.StatusOK {
		logger.Debugf("Skip %s with status %d", currentURL, resp.StatusCode)
		return
	}

	mediaType, _ := utils.GetMediaType(resp.Header)
	if mediaType != "text/html" {
		logger.Errorf("Non-HTML response: %s", currentURL)
		return
	}

	if !self.skipCMSCheck {
		if cms := self.detectCMS(string(resp.Body)); cms != "" {
			logger.Warnf("CMS detected: %s - %s", currentURL, cms)
			return
		}
	}

	self.processLinks(resp, currentURL, depth, sqliChecks)
	self.processForms(resp, currentURL, sqliChecks)
}

func (self *Scanner) processLinks(resp *ResponseWrapper, baseURL string, depth int, sqliChecks chan<- SQLiCheck) {
	links, _ := utils.ExtractLinks(resp.Body, baseURL)
	for _, link := range links {
		link, err := utils.StripFragment(link)
		if err != nil || !utils.IsSameHost(link, baseURL) || self.isIgnoredResource(link) || self.isVisited(link) {
			continue
		}

		if depth > 0 {
			self.wg.Add(1)
			self.sem <- struct{}{}
			go self.crawl(link, depth-1, baseURL, sqliChecks)
		}

		checkURL, checkParams, _ := utils.SplitURLParams(link)
		//logger.Debugf("Split URL params: %s, %v", checkURL, checkParams)

		if len(checkParams) == 0 {
			checkURL = self.injectSQLiPayload(checkURL)
		}

		sqliChecks <- SQLiCheck{Method: http.MethodGet, URL: checkURL, Params: checkParams, Referer: baseURL}
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

func (self *Scanner) processForms(resp *ResponseWrapper, baseURL string, sqliChecks chan<- SQLiCheck) {
	forms, _ := utils.ExtractForms(resp.Body, baseURL)
	for _, form := range forms {
		// Пропускаем формы, ведущие на сторонние домены
		if !utils.IsSameHost(form.Action, baseURL) {
			continue
		}
		fieldsJson, _ := json.Marshal(form.Fields)
		logger.Debugf("Form found: Method=%s, Action=%s, Fields=%s", form.Method, form.Action, string(fieldsJson))
		sqliChecks <- SQLiCheck{Method: form.Method, URL: form.Action, Params: self.autoFillFields(form.Fields), Referer: baseURL}
	}
}

// Добавляет кавычки в конец URL либо перед финальным "/"
func (self *Scanner) injectSQLiPayload(rawURL string) string {
	// null-bytes в C/C++ используется для обозначения конца строки (которая не более
	// чем массив байт). Подставив %00 в какой-то параметр, мы можем "обрезать" строку
	// и выполнить произвольный SQL-запрос. Но есть одно НО: сайты, как правило,
	// работают за Nginx, который отдает 404, если %00 встречается в самом URL.
	// Поэтому его нужно кодировать 2 раза, то есть использовать %2500.
	payload := url.QueryEscape(quotes + url.QueryEscape(nullByte))
	if strings.Count(rawURL, "/") > 3 && strings.HasSuffix(rawURL, "/") {
		return rawURL[:len(rawURL)-1] + payload + "/"
	}
	return rawURL + payload
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
		SQLiDetails: *details,
		ResultAt:    time.Now().Local().String(),
	}
}

func (self *Scanner) detectSQLi(check SQLiCheck) (bool, *SQLiDetails) {
	handle := func(params map[string]string) (string, int, string) {
		resp, _ := self.sendRequest(check.Method, check.URL, params, check.Referer)
		htmlContent := string(resp.Body)
		errorMessage := sqlErrorPattern.FindString(htmlContent)
		if errorMessage == "" {
			return "", 0, ""
		}
		title := utils.ExtractTitle(htmlContent)
		return errorMessage, resp.StatusCode, title
	}

	if len(check.Params) == 0 {
		logger.Debugf("Check SQLi: %s %s", check.Method, check.URL)
		errorMessage, status, title := handle(nil)
		if errorMessage != "" {
			return true, &SQLiDetails{ErrorMessage: errorMessage, StatusCode: status, PageTitle: title}
		}
	} else {
		payload := quotes
		if self.hasBody(check.Method) {
			payload += nullByte
		} else {
			// Тут так же кодируем null-byte, чтобы в итоге он превратился в %2500
			payload += url.QueryEscape(nullByte)
		}
		count := 0
		for param := range check.Params {
			if count >= self.maxCheckParams {
				break
			}
			params := utils.CopyStringMap(check.Params)
			params[param] += payload
			logger.Debugf("Check SQLi: %s %s; param=%q", check.Method, check.URL, param)
			errorMessage, status, title := handle(params)
			if errorMessage != "" {
				return true, &SQLiDetails{ErrorMessage: errorMessage, VulnParam: param, PageTitle: title, StatusCode: status}
			}
			count++
		}
	}
	return false, nil
}

func (self *Scanner) Scan(urls []string) <-chan ScanResult {
	logger.Infof("🚀 Scanning started.")
	logger.Debugf("🔍 Scanning %d URLs", len(urls))
	sqliChecks := make(chan SQLiCheck)
	results := make(chan ScanResult)
	go func() {
		defer func() {
			close(sqliChecks)
			close(results)
			logger.Infof("🎉 Scanning finished!")
			logger.Debugf("Total visited links: %d", utils.SyncMapSize(&self.visited))
			logger.Debugf("Total checks: %d", utils.SyncMapSize(&self.checked))
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
			go self.crawl(url, self.crawlDepth, defaultReferer, sqliChecks)
		}
		self.wg.Wait()
	}()
	return results
}

func (self *Scanner) setHeaders(req *retryablehttp.Request, referer string) {
	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.8",
		"User-Agent":      self.userAgent,
		"Referer":         referer,
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
	".aac", ".apk", ".avi", ".bak", ".bin",
	".bmp", ".csv", ".dmg", ".doc", ".docx",
	".eot", ".epub", ".exe", ".flac", ".flv",
	".gif", ".gz", ".ico", ".iso", ".jar",
	".jpeg", ".jpg", ".json", ".log", ".m4a",
	".mobi", ".mkv", ".mov", ".mp3", ".mp4",
	".odt", ".ogg", ".ods", ".pdf", ".png",
	".ppt", ".pptx", ".psd", ".rar", ".svg",
	".swf", ".tar", ".tiff", ".txt", ".wav",
	".webp", ".woff", ".woff2", ".xls", ".xlsx",
	".xml", ".zip", ".7z", ".aac", ".ttf",
	".otf",
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
