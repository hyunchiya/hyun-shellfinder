package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	_ "github.com/mattn/go-sqlite3"
)

// Config struktur
type Config struct {
	Threads         int      `json:"threads"`
	Timeout         int      `json:"timeout"`
	UserAgent       string   `json:"user_agent"`
	ProxyURL        string   `json:"proxy_url"`
	MaxDepth        int      `json:"max_depth"`
	APIEndpoint     string   `json:"api_endpoint"`
	TakeScreenshots bool     `json:"take_screenshots"`
	SaveToDB        bool     `json:"save_to_db"`
	CustomHeaders   []Header `json:"custom_headers"`
	WordlistFiles   []string `json:"wordlist_files"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CMSInfo struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Theme     string   `json:"theme"`
	Plugins   []string `json:"plugins"`
	Certainty int      `json:"certainty"`
	AdminURL  string   `json:"admin_url"`
	LoginURL  string   `json:"login_url"`
}

type Finding struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ScanResult struct {
	URL          string      `json:"url"`
	IP           string      `json:"ip"`
	Status       string      `json:"status"`
	StatusCode   int         `json:"status_code"`
	CMS          CMSInfo     `json:"cms"`
	Findings     []Finding   `json:"findings"`
	Depth        int         `json:"depth"`
	Timestamp    time.Time   `json:"timestamp"`
	Screenshot   string      `json:"screenshot,omitempty"`
	Headers      http.Header `json:"headers"`
	Title        string      `json:"title"`
	Technologies []string    `json:"technologies"`
}

type ScanSummary struct {
	URL      string
	Status   string
	CMS      string
	Findings int
}

var (
	config            Config
	db                *sql.DB
	httpClient        *http.Client
	wordlist          []string
	joomlaPatterns    []string
	wordpressPatterns []string
	visitedURLs       = sync.Map{}
	mu                sync.Mutex
	resultsChan       = make(chan ScanResult, 1000)
	totalScanned      = 0
)

func main() {
	// Parse flags
	var (
		domainFile   = flag.String("f", "list.txt", "File berisi list domain")
		outputFile   = flag.String("o", "results.json", "Output file")
		configFile   = flag.String("c", "config.json", "Config file")
		proxy        = flag.String("proxy", "", "Proxy URL (http://user:pass@proxy:port)")
		depth        = flag.Int("depth", 3, "Maximum depth for recursive scanning")
		threads      = flag.Int("t", 15, "Number of threads")
		screenshots  = flag.Bool("screenshots", false, "Take screenshots")
		apiURL       = flag.String("api", "", "API endpoint for results")
		wordlistFile = flag.String("wordlist", "", "Custom wordlist file")
		rateLimit    = flag.Int("rate", 100, "Rate limit (ms between requests)")
	)
	flag.Parse()

	// Load config
	loadConfig(*configFile)

	// Override with flags
	if *proxy != "" {
		config.ProxyURL = *proxy
	}
	if *depth > 0 {
		config.MaxDepth = *depth
	}
	if *threads > 0 {
		config.Threads = *threads
	}
	config.TakeScreenshots = *screenshots
	if *apiURL != "" {
		config.APIEndpoint = *apiURL
	}
	if *wordlistFile != "" {
		config.WordlistFiles = append(config.WordlistFiles, *wordlistFile)
	}

	printBanner()

	// Load wordlists
	loadWordlists()

	// Initialize HTTP client with proxy support
	initHTTPClient(*rateLimit)

	// Read domains
	domains, err := readDomains(*domainFile)
	if err != nil {
		log.Fatalf("Error reading domains: %v", err)
	}

	fmt.Printf("📊 Loaded %d domains\n", len(domains))
	fmt.Printf("⚡ Threads: %d | Depth: %d | Timeout: %ds\n",
		config.Threads, config.MaxDepth, config.Timeout)
	if config.ProxyURL != "" {
		fmt.Printf("🔗 Using proxy: %s\n", maskProxyURL(config.ProxyURL))
	}
	fmt.Printf("📝 Wordlist patterns: %d\n", len(wordlist)+len(joomlaPatterns)+len(wordpressPatterns))
	fmt.Println("============================================================")

	// Start scanner
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.Threads)
	startTime := time.Now()

	// Progress tracker
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			scanned := totalScanned
			mu.Unlock()
			fmt.Printf("\r⏳ Progress: %d/%d (%.1f%%)", scanned, len(domains),
				float64(scanned)/float64(len(domains))*100)
		}
	}()

	// Process results
	go processResults(*outputFile)

	// Scan domains
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := scanDomain(d, 0)
			mu.Lock()
			totalScanned++
			mu.Unlock()
			resultsChan <- result
		}(domain)
	}

	wg.Wait()
	close(resultsChan)

	if config.SaveToDB {
		generateReports(startTime, len(domains))
	} else {
		duration := time.Since(startTime)
		generateSummaryReport(duration, len(domains))
	}
}

func loadConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("⚠️ Using default config: %v", err)
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Printf("⚠️ Error parsing config: %v", err)
	}
}

func loadWordlists() {
	wordlist = []string{}

	for _, file := range config.WordlistFiles {
		patterns, err := loadPatternsFromFile(file)
		if err != nil {
			log.Printf("⚠️ Could not load %s: %v", file, err)
			continue
		}

		switch file {
		case "joomla_patterns.txt":
			joomlaPatterns = patterns
		case "wordpress_patterns.txt":
			wordpressPatterns = patterns
		default:
			wordlist = append(wordlist, patterns...)
		}
	}

	// Add your custom patterns
	customPatterns := []string{
		"gacor",
		"maxwin",
		"child_stdin, child_stdout = os.popen2(base64.b64decode(cmd))",
		"gzinflate(base64_decode(",
		"<!--#exec cmd=",
		"eval(base64_decode(",
		"eval(htmlspecialchars_decode(urldecode(base64_decode(",
		"eval(str_rot13(gzinflate(str_rot13(base64_decode(",
		"eval(strrev(htmlspecialchars_decode(gzinflate(base64_decode(",
		";@eval(",
		"<?php error_reporting(0);ini_set(\"display_errors\", 0);",
		"if($_POST){if(@copy($_FILES['__']['tmp_name'], $_FILES['__']['name'])",
		"system(base64_decode(",
		"exec(base64_decode(",
		"@eval($_POST[",
		"$_GET['cmd']",
		"if($_POST['cmd'])",
		"$_REQUEST['cmd']",
		"@fopen($_FILES[",
		"if(isset($_REQUEST['cmd']))",
		"shell_exec(base64_decode(",
		"@system(base64_decode(",
		"@eval(gzinflate(base64_decode(",
		"chunk_split(base64_encode(",
		"gzuncompress(base64_decode($",
		"ActiveXObject(\"WScript.Shell\").Run(",
		"@shell_exec($",
		"<?php echo(str_replace('<','',$_POST['cmd']));?",
		"curl_setopt($ch,CURLOPT_RETURNTRANSFER,TRUE);",
		"eval(htmlspecialchars_decode(gzinflate(base64_decode",
		"@ob_start(); @passthru($);",
		"base64_decode('c3RyX3JvdDEz');",
		"base64_decode('Z3ppbmZsYXRl');",
		"eval(gzuncompress(base64_decode(str_rot13",
		"base_convert(bin2hex($",
		"base_convert(bin2hex(substr($",
	}

	wordlist = append(wordlist, customPatterns...)
	log.Printf("✅ Loaded %d patterns from wordlists", len(wordlist))
}

func loadPatternsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, scanner.Err()
}

func initDatabase(filename string) {
	var err error
	db, err = sql.Open("sqlite3", filename)
	if err != nil {
		log.Fatalf("❌ Database error: %v", err)
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT UNIQUE,
			ip TEXT,
			status TEXT,
			status_code INTEGER,
			cms_name TEXT,
			cms_version TEXT,
			depth INTEGER,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER,
			type TEXT,
			path TEXT,
			evidence TEXT,
			severity TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS technologies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER,
			name TEXT,
			version TEXT,
			FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			log.Printf("⚠️ Database init error: %v", err)
		}
	}
}

func initHTTPClient(rateLimit int) {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	httpClient = &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

type rateLimitedTransport struct {
	transport http.RoundTripper
	limiter   *time.Ticker
}

func (r *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-r.limiter.C
	return r.transport.RoundTrip(req)
}

func readDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.HasPrefix(line, "http") {
			line = "https://" + line
		}

		line = strings.TrimSuffix(line, "/")
		domains = append(domains, line)
	}
	return domains, scanner.Err()
}

func scanDomain(baseURL string, depth int) ScanResult {
	if _, visited := visitedURLs.LoadOrStore(baseURL, true); visited {
		return ScanResult{URL: baseURL, Status: "SKIPPED"}
	}

	result := ScanResult{
		URL:       baseURL,
		Depth:     depth,
		Timestamp: time.Now(),
		Status:    "STARTED",
	}

	// Make request
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		result.Status = "ERROR"
		result.Findings = append(result.Findings, Finding{
			Type:     "REQUEST_ERROR",
			Evidence: err.Error(),
			Severity: "LOW",
		})
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	for _, header := range config.CustomHeaders {
		req.Header.Set(header.Name, header.Value)
	}

	// Execute request
	resp, err := httpClient.Do(req)
	if err != nil {
		result.Status = "ERROR"
		result.Findings = append(result.Findings, Finding{
			Type:     "CONNECTION_ERROR",
			Evidence: err.Error(),
			Severity: "LOW",
		})
		return result
	}
	defer resp.Body.Close()

	// Read response
	body, _ := io.ReadAll(resp.Body)
	content := string(body)
	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header
	result.Status = "SCANNED"

	// Get page title
	if titleMatch := regexp.MustCompile(`<title>(.*?)</title>`).FindStringSubmatch(content); len(titleMatch) > 1 {
		result.Title = titleMatch[1]
	}

	// Detect CMS and technologies
	result.CMS = detectCMS(baseURL, content, resp)
	result.Technologies = detectTechnologies(content, resp)

	// Advanced shell scanning
	result.Findings = advancedShellScan(baseURL, content, result.CMS.Name, resp)

	// Take screenshot if enabled
	if config.TakeScreenshots && depth == 0 && result.StatusCode == 200 {
		if screenshotPath := takeScreenshot(baseURL); screenshotPath != "" {
			result.Screenshot = screenshotPath
		}
	}

	// Recursive scanning
	if depth < config.MaxDepth && len(result.Findings) == 0 {
		links := extractLinks(baseURL, content)
		for _, link := range links {
			if !isExternalLink(link, baseURL) && !isBlacklisted(link) {
				if !strings.Contains(link, "?") || depth < 2 {
					nestedResult := scanDomain(link, depth+1)
					for _, finding := range nestedResult.Findings {
						if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
							result.Findings = append(result.Findings, finding)
						}
					}
				}
			}
		}
	}

	// Categorize status
	if len(result.Findings) > 0 {
		result.Status = "VULNERABLE"
	} else if result.StatusCode >= 400 {
		result.Status = "ERROR"
	} else {
		result.Status = "SAFE"
	}

	return result
}

func isExternalLink(link, baseURL string) bool {
	parsedLink, err1 := url.Parse(link)
	parsedBase, err2 := url.Parse(baseURL)

	if err1 != nil || err2 != nil {
		return true
	}

	return parsedLink.Host != "" && parsedLink.Host != parsedBase.Host
}

func isBlacklisted(link string) bool {
	blacklist := []string{
		"logout", "signout", "exit", "logoff",
		".jpg", ".png", ".gif", ".css", ".js",
		".pdf", ".zip", ".rar", ".exe", ".mp4",
	}

	for _, pattern := range blacklist {
		if strings.Contains(strings.ToLower(link), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func advancedShellScan(baseURL, content, cms string, resp *http.Response) []Finding {
	var findings []Finding

	// Combine all patterns
	allPatterns := wordlist
	switch cms {
	case "Joomla":
		allPatterns = append(allPatterns, joomlaPatterns...)
	case "WordPress":
		allPatterns = append(allPatterns, wordpressPatterns...)
	}

	// Check string patterns
	for _, pattern := range allPatterns {
		if strings.Contains(content, pattern) {
			findings = append(findings, Finding{
				Type:        "SHELL_PATTERN",
				Path:        baseURL,
				Evidence:    truncate(pattern, 100),
				Severity:    getSeverity(pattern),
				Description: "Found shell pattern in page content",
			})
		}
	}

	// Check regex patterns
	regexPatterns := []*regexp.Regexp{
		regexp.MustCompile(`eval\s*\(\s*base64_decode\s*\(`),
		regexp.MustCompile(`gzinflate\s*\(\s*base64_decode\s*\(`),
		regexp.MustCompile(`system\s*\(\s*\$_`),
		regexp.MustCompile(`shell_exec\s*\(`),
		regexp.MustCompile(`passthru\s*\(`),
		regexp.MustCompile(`exec\s*\(`),
		regexp.MustCompile(`assert\s*\(`),
		regexp.MustCompile(`preg_replace\s*\(.*/e`),
		regexp.MustCompile(`\x28\x29\x7b\x28.*\x7d`),
		regexp.MustCompile(`\x24\x5f\x50\x4f\x53\x54\x5b.*\x5d`),
	}

	for _, re := range regexPatterns {
		if matches := re.FindAllString(content, -1); len(matches) > 0 {
			for _, match := range matches {
				findings = append(findings, Finding{
					Type:        "SHELL_REGEX",
					Path:        baseURL,
					Evidence:    truncate(match, 100),
					Severity:    "CRITICAL",
					Description: "Regex match for shell code",
				})
			}
		}
	}

	// Check for encoded content
	if encoded := findEncodedContent(content); encoded != "" {
		findings = append(findings, Finding{
			Type:        "ENCODED_CONTENT",
			Path:        baseURL,
			Evidence:    truncate(encoded, 100),
			Severity:    "HIGH",
			Description: "Found potentially encoded malicious content",
		})
	}

	// Check suspicious headers
	for header, values := range resp.Header {
		for _, value := range values {
			if isSuspiciousHeader(header, value) {
				findings = append(findings, Finding{
					Type:        "SUSPICIOUS_HEADER",
					Path:        baseURL,
					Evidence:    fmt.Sprintf("%s: %s", header, value),
					Severity:    "MEDIUM",
					Description: "Suspicious HTTP header detected",
				})
			}
		}
	}

	// Check common shell paths
	shellPaths := getCommonShellPaths(cms)
	for _, path := range shellPaths {
		fullURL := baseURL + path
		if checkURLExists(fullURL) {
			findings = append(findings, Finding{
				Type:        "SHELL_FILE",
				Path:        path,
				Evidence:    "File exists",
				Severity:    "CRITICAL",
				Description: "Common shell file found",
			})
		}
	}

	return findings
}

func findEncodedContent(content string) string {
	// Look for base64 encoded strings longer than 100 chars
	re := regexp.MustCompile(`base64_decode\(['"]([A-Za-z0-9+/=]{100,})['"]\)`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}

	// Look for hex encoded strings
	re = regexp.MustCompile(`\\x[0-9a-fA-F]{2,}`)
	if matches := re.FindAllString(content, 5); len(matches) > 0 {
		return strings.Join(matches, " ")
	}

	return ""
}

func isSuspiciousHeader(header, value string) bool {
	suspiciousHeaders := map[string][]string{
		"X-Powered-By": {"PHP", "ASP.NET", "JSP"},
		"Server":       {"nginx", "apache", "IIS"},
	}

	for h, patterns := range suspiciousHeaders {
		if strings.EqualFold(header, h) {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(value), strings.ToLower(pattern)) {
					return true
				}
			}
		}
	}

	// Check for unusual headers
	unusualHeaders := []string{
		"X-Backdoor", "X-Shell", "X-Cmd", "X-Eval",
	}

	for _, unusual := range unusualHeaders {
		if strings.EqualFold(header, unusual) {
			return true
		}
	}

	return false
}

func getCommonShellPaths(cms string) []string {
	var paths []string

	switch cms {
	case "WordPress":
		paths = []string{
			"/wp-content/themes/twentyfifteen/404.php",
			"/wp-content/uploads/shell.php",
			"/wp-content/plugins/hello.php",
			"/wp-includes/js/jquery/jquery.js?cmd=",
			"/wp-config.php.bak",
			"/wp-admin/admin-ajax.php",
			"/xmlrpc.php",
			"/wp-login.php",
		}
	case "Joomla":
		paths = []string{
			"/components/com_wrapper/wrapper.php",
			"/modules/mod_wrapper/wrapper.php",
			"/templates/beez/index.php",
			"/administrator/components/com_admin/admin.php",
			"/plugins/system/plugin.php",
			"/configuration.php.bak",
			"/htaccess.txt",
			"/joomla.xml",
		}
	default:
		paths = []string{
			"/cmd.php", "/wso.php", "/c99.php", "/r57.php",
			"/shell.php", "/upload.php", "/b374k.php",
			"/config.php.bak", "/.htaccess", "/.user.ini",
			"/test.php", "/info.php", "/phpinfo.php",
		}
	}

	return paths
}

func checkURLExists(url string) bool {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", config.UserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func detectCMS(baseURL, content string, resp *http.Response) CMSInfo {
	cms := CMSInfo{Name: "Unknown", Certainty: 0}

	wpIndicators := []string{
		"wp-content", "wp-includes", "wp-admin",
		"WordPress", "wordpress", "/wp-",
		"wp-json", "xmlrpc.php",
	}

	joomlaIndicators := []string{
		"joomla", "Joomla", "/components/com_",
		"/modules/mod_", "/templates/", "index.php?option=com_",
		"Joomla! CMS",
	}

	wpScore := 0
	joomlaScore := 0

	for _, indicator := range wpIndicators {
		if strings.Contains(strings.ToLower(content), strings.ToLower(indicator)) {
			wpScore++
		}
	}

	for _, indicator := range joomlaIndicators {
		if strings.Contains(strings.ToLower(content), strings.ToLower(indicator)) {
			joomlaScore++
		}
	}

	if strings.Contains(resp.Header.Get("X-Powered-By"), "WordPress") {
		wpScore += 3
	}
	if strings.Contains(resp.Header.Get("X-Powered-By"), "Joomla") {
		joomlaScore += 3
	}
	if strings.Contains(resp.Header.Get("X-Generator"), "WordPress") {
		wpScore += 2
	}
	if strings.Contains(resp.Header.Get("X-Generator"), "Joomla") {
		joomlaScore += 2
	}

	if strings.Contains(content, "generator\" content=\"WordPress") {
		wpScore += 5
		if version := regexp.MustCompile(`WordPress (\d+\.\d+(\.\d+)?)`).FindStringSubmatch(content); len(version) > 1 {
			cms.Version = version[1]
		}
	}

	if strings.Contains(content, "generator\" content=\"Joomla") {
		joomlaScore += 5
		if version := regexp.MustCompile(`Joomla! (\d+\.\d+(\.\d+)?)`).FindStringSubmatch(content); len(version) > 1 {
			cms.Version = version[1]
		}
	}

	if wpScore > joomlaScore && wpScore >= 3 {
		cms.Name = "WordPress"
		cms.Certainty = min(wpScore*10, 95)
		cms.AdminURL = baseURL + "/wp-admin"
		cms.LoginURL = baseURL + "/wp-login.php"

		if theme := regexp.MustCompile(`/wp-content/themes/([^/]+)/`).FindStringSubmatch(content); len(theme) > 1 {
			cms.Theme = theme[1]
		}

	} else if joomlaScore > wpScore && joomlaScore >= 3 {
		cms.Name = "Joomla"
		cms.Certainty = min(joomlaScore*10, 95)
		cms.AdminURL = baseURL + "/administrator"
		cms.LoginURL = baseURL + "/administrator/index.php"
	}

	return cms
}

func detectTechnologies(content string, resp *http.Response) []string {
	var tech []string

	server := resp.Header.Get("Server")
	if server != "" {
		tech = append(tech, "Server: "+server)
	}

	if strings.Contains(server, "PHP") || strings.Contains(content, "<?php") {
		tech = append(tech, "PHP")
	}

	frameworks := map[string][]string{
		"Laravel":     {"laravel", "csrf-token"},
		"Symfony":     {"symfony", "sf2"},
		"CodeIgniter": {"codeigniter", "ci_session"},
		"Yii":         {"yii", "yii.js"},
		"React":       {"react.", "react-dom"},
		"Vue.js":      {"vue.", "vue-router"},
		"Angular":     {"angular", "ng-"},
		"jQuery":      {"jquery", "jQuery"},
		"Bootstrap":   {"bootstrap", "btn-"},
	}

	for name, indicators := range frameworks {
		for _, indicator := range indicators {
			if strings.Contains(strings.ToLower(content), strings.ToLower(indicator)) {
				tech = append(tech, name)
				break
			}
		}
	}

	return tech
}

func extractLinks(baseURL, content string) []string {
	var links []string

	hrefRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := hrefRegex.FindAllStringSubmatch(content, -1)

	base, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	srcRegex := regexp.MustCompile(`src=["']([^"']+)["']`)
	matches = append(matches, srcRegex.FindAllStringSubmatch(content, -1)...)

	actionRegex := regexp.MustCompile(`action=["']([^"']+)["']`)
	matches = append(matches, actionRegex.FindAllStringSubmatch(content, -1)...)

	unique := make(map[string]bool)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		rawURL := match[1]

		if strings.HasPrefix(rawURL, "javascript:") ||
			strings.HasPrefix(rawURL, "mailto:") ||
			strings.HasPrefix(rawURL, "tel:") ||
			strings.HasPrefix(rawURL, "#") {
			continue
		}

		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		resolved := base.ResolveReference(parsed)

		finalURL := resolved.String()
		finalURL = strings.Split(finalURL, "#")[0]
		finalURL = strings.Split(finalURL, "?")[0]

		if !unique[finalURL] && finalURL != "" {
			unique[finalURL] = true
			links = append(links, finalURL)
		}
	}

	return links
}

func takeScreenshot(url string) string {
	os.MkdirAll("screenshots", 0755)

	filename := fmt.Sprintf("screenshots/%s_%d.png",
		strings.ReplaceAll(strings.ReplaceAll(url, "://", "_"), "/", "_"),
		time.Now().Unix())

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1920, 1080),
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(3*time.Second),
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		log.Printf("❌ Screenshot failed for %s: %v", url, err)
		return ""
	}

	if err := os.WriteFile(filename, buf, 0644); err != nil {
		log.Printf("❌ Failed to save screenshot: %v", err)
		return ""
	}

	return filename
}

func processResults(outputFile string) {
	var results []ScanResult

	for result := range resultsChan {
		if config.SaveToDB {
			saveToDatabase(result)
		}

		if config.APIEndpoint != "" {
			sendToAPI(result)
		}

		printResult(result)

		results = append(results, result)
	}

	saveToJSON(outputFile, results)
}

func saveToDatabase(result ScanResult) {
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT OR REPLACE INTO scans 
		(url, ip, status, status_code, cms_name, cms_version, depth, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, result.URL, result.IP, result.Status, result.StatusCode,
		result.CMS.Name, result.CMS.Version, result.Depth, result.Timestamp)

	if err != nil {
		return
	}

	scanID, _ := res.LastInsertId()

	for _, finding := range result.Findings {
		tx.Exec(`
			INSERT INTO findings (scan_id, type, path, evidence, severity, timestamp)
			VALUES (?, ?, ?, ?, ?, ?)
		`, scanID, finding.Type, finding.Path, finding.Evidence, finding.Severity, time.Now())
	}

	for _, tech := range result.Technologies {
		tx.Exec(`
			INSERT INTO technologies (scan_id, name)
			VALUES (?, ?)
		`, scanID, tech)
	}

	tx.Commit()
}

func sendToAPI(result ScanResult) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", config.APIEndpoint,
		strings.NewReader(string(jsonData)))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", config.UserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func printResult(result ScanResult) {
	colorReset := "\033[0m"
	colorRed := "\033[31m"
	colorGreen := "\033[32m"
	colorYellow := "\033[33m"
	colorBlue := "\033[34m"
	colorPurple := "\033[35m"

	var statusColor string
	switch result.Status {
	case "VULNERABLE":
		statusColor = colorRed
	case "SAFE":
		statusColor = colorGreen
	case "ERROR":
		statusColor = colorYellow
	default:
		statusColor = colorBlue
	}

	fmt.Printf("\n%s[%s]%s %s\n", statusColor, result.Status, colorReset, result.URL)
	fmt.Printf("  CMS: %s %s (%d%%)\n", result.CMS.Name, result.CMS.Version, result.CMS.Certainty)
	fmt.Printf("  Status Code: %d\n", result.StatusCode)

	if len(result.Findings) > 0 {
		fmt.Printf("  Findings (%d):\n", len(result.Findings))
		for _, finding := range result.Findings {
			var severityColor string
			switch finding.Severity {
			case "CRITICAL":
				severityColor = colorRed
			case "HIGH":
				severityColor = colorPurple
			case "MEDIUM":
				severityColor = colorYellow
			default:
				severityColor = colorBlue
			}
			fmt.Printf("    %s[%s]%s %s: %s\n",
				severityColor, finding.Severity, colorReset,
				finding.Type, truncate(finding.Evidence, 50))
		}
	}
}

func saveToJSON(filename string, results []ScanResult) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("❌ Failed to create output file: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		log.Printf("❌ Failed to write JSON: %v", err)
	}
}

func generateReports(startTime time.Time, totalDomains int) {
	duration := time.Since(startTime)

	if db != nil {
		generateHTMLReport()
	}

	generateSummaryReport(duration, totalDomains)
}

func generateHTMLReport() {
	if db == nil {
		return
	}
	rows, err := db.Query(`
		SELECT s.url, s.status, s.cms_name, COUNT(f.id) as findings_count
		FROM scans s
		LEFT JOIN findings f ON s.id = f.scan_id
		GROUP BY s.id
		ORDER BY findings_count DESC
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	var scans []ScanSummary
	for rows.Next() {
		var scan ScanSummary
		rows.Scan(&scan.URL, &scan.Status, &scan.CMS, &scan.Findings)
		scans = append(scans, scan)
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>ShellFinder Report</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gray-50">
    <div class="container mx-auto px-4 py-8">
        <div class="bg-white rounded-lg shadow-lg p-6 mb-8">
            <h1 class="text-3xl font-bold text-gray-800 mb-2">
                <i class="fas fa-shield-alt text-blue-500 mr-3"></i>
                ShellFinder Security Report
            </h1>
            <p class="text-gray-600">Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-blue-50 rounded-lg p-6">
                <div class="flex items-center">
                    <i class="fas fa-globe text-blue-500 text-2xl mr-4"></i>
                    <div>
                        <p class="text-sm text-gray-600">Total Scanned</p>
                        <p class="text-2xl font-bold text-gray-800">` + fmt.Sprintf("%d", len(scans)) + `</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-red-50 rounded-lg p-6">
                <div class="flex items-center">
                    <i class="fas fa-exclamation-triangle text-red-500 text-2xl mr-4"></i>
                    <div>
                        <p class="text-sm text-gray-600">Vulnerable</p>
                        <p class="text-2xl font-bold text-gray-800">` + fmt.Sprintf("%d", countVulnerable(scans)) + `</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-green-50 rounded-lg p-6">
                <div class="flex items-center">
                    <i class="fas fa-check-circle text-green-500 text-2xl mr-4"></i>
                    <div>
                        <p class="text-sm text-gray-600">Clean</p>
                        <p class="text-2xl font-bold text-gray-800">` + fmt.Sprintf("%d", len(scans)-countVulnerable(scans)) + `</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow-lg overflow-hidden">
            <div class="px-6 py-4 border-b">
                <h2 class="text-xl font-semibold text-gray-800">Scan Results</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CMS</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Findings</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
`

	for _, scan := range scans {
		statusClass := "bg-green-100 text-green-800"
		if scan.Status == "VULNERABLE" {
			statusClass = "bg-red-100 text-red-800"
		} else if scan.Status == "ERROR" {
			statusClass = "bg-yellow-100 text-yellow-800"
		}

		findingsClass := "bg-gray-100 text-gray-800"
		if scan.Findings > 0 {
			if scan.Findings > 5 {
				findingsClass = "bg-red-100 text-red-800"
			} else {
				findingsClass = "bg-yellow-100 text-yellow-800"
			}
		}

		html += `<tr>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                ` + scan.URL + `
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                ` + scan.CMS + `
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ` + statusClass + `">
                    ` + scan.Status + `
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ` + findingsClass + `">
                    ` + fmt.Sprintf("%d", scan.Findings) + `
                </span>
            </td>
        </tr>`
	}

	html += `</tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>`

	os.WriteFile("report.html", []byte(html), 0644)
	log.Println("📊 HTML report generated: report.html")
}

func countVulnerable(scans []ScanSummary) int {
	count := 0
	for _, scan := range scans {
		if scan.Findings > 0 || scan.Status == "VULNERABLE" {
			count++
		}
	}
	return count
}

func generateSummaryReport(duration time.Duration, totalDomains int) {
	file, err := os.Create("summary.txt")
	if err != nil {
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	writer.WriteString("=== SHELLFINDER SCAN SUMMARY ===\n")
	writer.WriteString(fmt.Sprintf("Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Duration: %v\n", duration))
	writer.WriteString(fmt.Sprintf("Total Domains: %d\n", totalDomains))
	writer.WriteString(fmt.Sprintf("Completed: %d\n", totalScanned))
	writer.WriteString("\n")

	writer.WriteString("Detailed Results:\n")
	writer.WriteString("=================\n")

	if db == nil {
		writer.WriteString("\nDetailed results from database are unavailable (CGO disabled or SaveToDB is false).\n")
		writer.Flush()
		log.Println("📄 Summary report generated: summary.txt (Without database details)")
		return
	}

	rows, err := db.Query(`
       SELECT s.url, s.status, s.cms_name, s.cms_version,
		       COUNT(f.id) as findings_count,
		       GROUP_CONCAT(f.evidence, ' | ') as evidences
		FROM scans s
		LEFT JOIN findings f ON s.id = f.scan_id
		WHERE s.status != 'SKIPPED'
		GROUP BY s.id
		ORDER BY findings_count DESC
	`)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var url, status, cmsName, cmsVersion, evidences string
			var findingsCount int
			rows.Scan(&url, &status, &cmsName, &cmsVersion, &findingsCount, &evidences)

			writer.WriteString(fmt.Sprintf("\nURL: %s\n", url))
			writer.WriteString(fmt.Sprintf("Status: %s\n", status))
			writer.WriteString(fmt.Sprintf("CMS: %s %s\n", cmsName, cmsVersion))
			writer.WriteString(fmt.Sprintf("Findings: %d\n", findingsCount))
			if evidences != "" {
				writer.WriteString(fmt.Sprintf("Evidence: %s\n", evidences))
			}
			writer.WriteString("---\n")
		}
	}

	writer.Flush()
	log.Println("📄 Summary report generated: summary.txt")
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maskProxyURL(proxyURL string) string {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return "***"
	}
	if parsed.User != nil {
		parsed.User = url.UserPassword("***", "***")
	}
	return parsed.String()
}

func getSeverity(pattern string) string {
	criticalPatterns := []string{"eval(", "system(", "shell_exec", "base64_decode", "gzinflate"}
	highPatterns := []string{"$_GET", "$_POST", "$_REQUEST", "exec(", "passthru"}

	for _, p := range criticalPatterns {
		if strings.Contains(pattern, p) {
			return "CRITICAL"
		}
	}

	for _, p := range highPatterns {
		if strings.Contains(pattern, p) {
			return "HIGH"
		}
	}

	return "MEDIUM"
}

func printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║                   SHELLFINDER v3.0                          ║
║        Advanced Joomla & WordPress Security Scanner         ║
║                     with AI-Powered Detection               ║
╚══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
