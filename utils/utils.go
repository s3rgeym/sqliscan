package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"io"
	"math/rand"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	html2 "golang.org/x/net/html"
)

// type Semaphore struct {
// 	sem chan struct{}
// 	wg  sync.WaitGroup
// }

// func NewSemaphore(size int) *Semaphore {
// 	return &Semaphore{
// 		sem: make(chan struct{}, size),
// 	}
// }

// func (s *Semaphore) Acquire() {
// 	s.wg.Add(1)
// 	s.sem <- struct{}{}
// }
// func (s *Semaphore) Release() {
// 	<-s.sem
// 	s.wg.Done()
// }
// func (s *Semaphore) Wait() {
// 	s.wg.Wait()
// }

func ReadURLs(reader io.Reader) ([]string, error) {
	var urls []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, NormalizeUrl(line))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

func NormalizeUrl(u string) string {
	if !strings.Contains(u, "://") {
		return "http://" + u
	}
	return u
}

func URLJoin(baseUrl, path string) (string, error) {
	base, err := url.Parse(baseUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing base Url %q: %w", baseUrl, err)
	}

	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("error parsing path %q as Url: %w", path, err)
	}

	return base.ResolveReference(rel).String(), nil
}

func GetMediaType(header http.Header) (string, error) {
	contentType := header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	return mediaType, nil
}

func ExtractLinks(content []byte, baseUrl string) ([]string, error) {
	doc, err := html2.Parse(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	uniqueLinks := make(map[string]struct{})
	var f func(*html2.Node)
	f = func(n *html2.Node) {
		if n.Type == html2.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					link, err := URLJoin(baseUrl, attr.Val)
					if err != nil {
						continue
					}
					uniqueLinks[link] = struct{}{}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	links := make([]string, 0, len(uniqueLinks))
	for link := range uniqueLinks {
		links = append(links, link)
	}
	return links, nil
}

type FormData struct {
	Method string
	Action string
	Fields map[string]string
}

func ExtractForms(content []byte, baseUrl string) ([]FormData, error) {
	doc, err := html2.Parse(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML: %w", err)
	}

	var forms []FormData
	var f func(*html2.Node)
	f = func(n *html2.Node) {
		if n.Type == html2.ElementNode && n.Data == "form" {
			form := FormData{
				Fields: make(map[string]string),
			}

			for _, attr := range n.Attr {
				switch attr.Key {
				case "method":
					form.Method = strings.ToUpper(attr.Val)
				case "action":
					actionUrl, err := URLJoin(baseUrl, attr.Val)
					if err != nil {
						continue
					}
					form.Action = actionUrl
				}
			}

			if form.Method == "" {
				form.Method = "GET"
			}

			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html2.ElementNode && c.Data == "input" {
					var name, value string
					for _, attr := range c.Attr {
						switch attr.Key {
						case "name":
							name = attr.Val
						case "value":
							value = attr.Val
						}
					}
					if name != "" {
						form.Fields[name] = value
					}
				}
			}

			forms = append(forms, form)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(doc)
	return forms, nil
}

func ExtractTitle(htmlContent string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(htmlContent)

	if len(matches) < 2 {
		return ""
	}

	return html.UnescapeString(matches[1])
}

func ExtractHost(inputURL string) (string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}
	return NormalizePort(parsed.Host, parsed.Scheme), nil
}

func IsSameHost(targetURL, baseURL string) bool {
	target, err1 := url.Parse(targetURL)
	base, err2 := url.Parse(baseURL)

	if err1 != nil || err2 != nil {
		return false
	}

	targetHost := NormalizePort(target.Host, target.Scheme)
	baseHost := NormalizePort(base.Host, base.Scheme)
	return strings.ToLower(targetHost) == strings.ToLower(baseHost)
}

func NormalizePort(host, scheme string) string {
	if strings.HasSuffix(host, ":80") && scheme == "http" {
		return strings.TrimSuffix(host, ":80")
	}
	if strings.HasSuffix(host, ":443") && scheme == "https" {
		return strings.TrimSuffix(host, ":443")
	}
	return host
}

func StripFragment(inputURL string) (string, error) {
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	parsed.Fragment = ""
	return parsed.String(), nil
}

func SplitURLParams(inputURL string) (string, map[string]string, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", nil, err
	}

	params := make(map[string]string)
	queryParams := parsedURL.Query()
	for key, values := range queryParams {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	parsedURL.RawQuery = ""

	return parsedURL.String(), params, nil
}

func BuildQueryString(params map[string]string) string {
	var parts []string

	for key, value := range params {
		escapedKey := url.QueryEscape(key)
		escapedValue := url.QueryEscape(value)
		parts = append(parts, escapedKey+"="+escapedValue)
	}

	return strings.Join(parts, "&")
}

// func CopyMap(m map[string]interface{}) map[string]interface{} {
// 	cp := make(map[string]interface{})
// 	for k, v := range m {
// 		vm, ok := v.(map[string]interface{})
// 		if ok {
// 			cp[k] = CopyMap(vm)
// 		} else {
// 			cp[k] = v
// 		}
// 	}

// 	return cp
// }

func CopyStringMap(m map[string]string) map[string]string {
	cp := make(map[string]string)
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func SyncMapSize(m *sync.Map) int {
	size := 0
	m.Range(func(key, value interface{}) bool {
		size++
		return true
	})
	return size
}

func GenerateRandomUserAgent() string {
	// Возможные платформы
	platforms := []string{
		"(Windows NT 10.0; Win64; x64)",
		"(Macintosh; Intel Mac OS X 10_15_7)",
		"(X11; Linux x86_64)",
		"(Windows NT 6.1; Win64; x64)",
		"(Macintosh; Intel Mac OS X 10_14_6)",
	}

	// Случайный выбор платформы
	platform := platforms[rand.Intn(len(platforms))]

	// Генерация случайной мажорной версии Chrome (от 88 до 131)
	majorVersion := rand.Intn(131-88+1) + 88

	// Формирование User-Agent
	userAgent := fmt.Sprintf(
		"Mozilla/5.0 %s AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36",
		platform,
		majorVersion,
	)

	return userAgent
}

func SortKeys(params map[string]string) []string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
