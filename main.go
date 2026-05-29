package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	XRAYPath      = "./xray.exe"
	WorkerCount   = 20
	TestTimeout   = 10 * time.Second
	RetryCount    = 1
)

type ProxyConfig struct {
	URL         string
	Protocol    string // "trojan" or "vless"
	Address     string
	Port        string
	Password    string // For trojan
	UUID        string // For vless
	Encryption  string // For vless (usually "none")
	Flow        string // For vless
	Security    string
	SNI         string
	ALPN        string
	Fingerprint string
	Network     string
	Host        string
	Path        string
	HeaderType  string // For vless "type" parameter
	Mode        string // For vless
	RawURL      string
}

type TestResult struct {
	Config   *ProxyConfig
	Working  bool
	Latency  time.Duration
	Error    string
	HTTPCode int
}

type ResultStats struct {
	Total     int32
	Working   int32
	Dead      int32
	StartTime time.Time
}

var (
	activeTests int32
	stats       ResultStats
)

func ParseProxyURL(raw string) (*ProxyConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	config := &ProxyConfig{
		URL:    raw,
		RawURL: raw,
	}

	// Determine protocol
	if u.Scheme == "trojan" {
		config.Protocol = "trojan"
		if u.User != nil {
			config.Password = u.User.Username()
		}
	} else if u.Scheme == "vless" {
		config.Protocol = "vless"
		if u.User != nil {
			config.UUID = u.User.Username()
		}
	} else {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	config.Address = u.Hostname()
	config.Port = u.Port()
	if config.Port == "" {
		config.Port = "443"
	}

	// Parse query parameters
	query := u.Query()
	
	// Common parameters
	config.Security = query.Get("security")
	config.SNI = query.Get("sni")
	if config.SNI == "" {
		config.SNI = query.Get("peer")
	}
	config.ALPN = query.Get("alpn")
	config.Fingerprint = query.Get("fp")
	config.Network = query.Get("type")
	if config.Network == "" {
		config.Network = query.Get("network")
	}
	config.Host = query.Get("host")
	config.Path = query.Get("path")
	
	// VLESS-specific parameters
	if config.Protocol == "vless" {
		config.Encryption = query.Get("encryption")
		if config.Encryption == "" {
			config.Encryption = "none"
		}
		config.Flow = query.Get("flow")
		config.HeaderType = query.Get("headerType")
		if config.HeaderType == "" {
			config.HeaderType = query.Get("type") // Some use 'type' for header type
		}
		config.Mode = query.Get("mode")
	}

	// Set defaults
	if config.Security == "" {
		config.Security = "tls"
	}
	if config.Fingerprint == "" {
		config.Fingerprint = "chrome"
	}
	if config.Network == "" {
		config.Network = "tcp"
	}
	if config.ALPN == "" {
		config.ALPN = "http/1.1"
	}
	if config.Path == "" {
		config.Path = "/"
	}

	return config, nil
}

func BuildOutbound(config *ProxyConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"protocol": config.Protocol,
	}

	// Build settings based on protocol
	if config.Protocol == "trojan" {
		port, _ := strconv.Atoi(config.Port)
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  config.Address,
					"port":     port,
					"password": config.Password,
				},
			},
		}
	} else if config.Protocol == "vless" {
		port, _ := strconv.Atoi(config.Port)
		server := map[string]interface{}{
			"address":    config.Address,
			"port":       port,
			"id":         config.UUID,
			"encryption": config.Encryption,
		}
		if config.Flow != "" {
			server["flow"] = config.Flow
		}
		
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{server},
		}
	}

	// Build stream settings
	stream := map[string]interface{}{
		"network":  config.Network,
		"security": config.Security,
	}

	if config.Security == "tls" || config.Security == "reality" {
		alpnList := []string{}
		if config.ALPN != "" {
			alpnList = strings.Split(config.ALPN, ",")
		}
		if len(alpnList) == 0 {
			alpnList = []string{"http/1.1"}
		}
		
		tlsSettings := map[string]interface{}{
			"serverName":  config.SNI,
			"fingerprint": config.Fingerprint,
		}
		if len(alpnList) > 0 {
			tlsSettings["alpn"] = alpnList
		}
		
		if config.Security == "reality" {
			// Reality-specific settings
			tlsSettings["realitySettings"] = map[string]interface{}{
				"show": false,
			}
		}
		
		stream["tlsSettings"] = tlsSettings
	}

	// Network-specific settings
	switch config.Network {
	case "ws":
		wsSettings := map[string]interface{}{
			"path": config.Path,
		}
		if config.Host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": config.Host,
			}
		}
		stream["wsSettings"] = wsSettings
		
	case "grpc":
		stream["grpcSettings"] = map[string]interface{}{
			"serviceName": config.Path,
		}
		
	case "xhttp":
		// xhttp is similar to http/2
		stream["httpSettings"] = map[string]interface{}{
			"path": config.Path,
			"host": []string{config.Host},
		}
	}

	outbound["streamSettings"] = stream
	return outbound
}

func ensureDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

func startXrayWithConfig(config map[string]interface{}, configFile string) (*exec.Cmd, error) {
	// Ensure temp directory exists
	if err := ensureDir("temp"); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return nil, err
	}

	cmd := exec.Command(XRAYPath, "run", "-c", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		os.Remove(configFile)
		return nil, err
	}

	return cmd, nil
}

func testConfig(ctx context.Context, config *ProxyConfig, testPort int) *TestResult {
	result := &TestResult{
		Config:  config,
		Working: false,
	}

	startTime := time.Now()

	// Create temp config file
	configFile := fmt.Sprintf("temp/temp_%d_%d.json", testPort, time.Now().UnixNano())
	defer os.Remove(configFile)

	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "error",
		},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
				"port":     testPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  false,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			BuildOutbound(config),
		},
	}

	// Start Xray
	cmd, err := startXrayWithConfig(xrayConfig, configFile)
	if err != nil {
		result.Error = fmt.Sprintf("Xray start failed: %v", err)
		return result
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// Brief wait for Xray to be ready
	time.Sleep(150 * time.Millisecond)

	// Test through SOCKS proxy
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", testPort))
	
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   TestTimeout,
			KeepAlive: 0,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        1,
		IdleConnTimeout:     0,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   TestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	// Test endpoints
	testURLs := []string{
		"https://www.google.com/generate_204",
		"https://cloudflare.com/cdn-cgi/trace",
		"http://www.gstatic.com/generate_204",
	}

	for _, testURL := range testURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "close")
		
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 204 {
				result.Working = true
				result.HTTPCode = resp.StatusCode
				result.Latency = time.Since(startTime)
				return result
			}
			result.HTTPCode = resp.StatusCode
		}
	}

	result.Error = "All test endpoints failed"
	return result
}

func fastTCPCheck(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func worker(ctx context.Context, configs <-chan *ProxyConfig, results chan<- *TestResult, portBase int, wg *sync.WaitGroup) {
	defer wg.Done()
	
	port := portBase + int(atomic.AddInt32(&activeTests, 1))
	
	for config := range configs {
		// Quick TCP pre-filter
		addr := net.JoinHostPort(config.Address, config.Port)
		if !fastTCPCheck(addr, 2*time.Second) {
			results <- &TestResult{
				Config:  config,
				Working: false,
				Error:   "TCP connection failed",
			}
			atomic.AddInt32(&stats.Total, 1)
			atomic.AddInt32(&stats.Dead, 1)
			continue
		}
		
		// Full test
		result := testConfig(ctx, config, port)
		
		if result.Working {
			atomic.AddInt32(&stats.Working, 1)
			fmt.Printf("✓ WORKING | %s | %s | Latency: %v\n", 
				strings.ToUpper(config.Protocol), config.Address, result.Latency)
		} else {
			atomic.AddInt32(&stats.Dead, 1)
			fmt.Printf("✗ DEAD    | %s | %s | %s\n", 
				strings.ToUpper(config.Protocol), config.Address, result.Error)
		}
		
		atomic.AddInt32(&stats.Total, 1)
		results <- result
	}
}

func loadConfigsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var configs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Accept both trojan:// and vless:// URLs
			if strings.HasPrefix(line, "trojan://") || strings.HasPrefix(line, "vless://") {
				configs = append(configs, line)
			} else if !strings.Contains(line, "://") {
				// Assume trojan if no scheme
				configs = append(configs, "trojan://"+line)
			}
		}
	}
	return configs, scanner.Err()
}

func printFinalReport() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCAN COMPLETE")
	fmt.Printf("Total tested: %d\n", atomic.LoadInt32(&stats.Total))
	fmt.Printf("Working: %d\n", atomic.LoadInt32(&stats.Working))
	fmt.Printf("Dead: %d\n", atomic.LoadInt32(&stats.Dead))
	if atomic.LoadInt32(&stats.Total) > 0 {
		fmt.Printf("Success rate: %.2f%%\n", 
			float64(atomic.LoadInt32(&stats.Working))/float64(atomic.LoadInt32(&stats.Total))*100)
	}
	fmt.Printf("Duration: %v\n", time.Since(stats.StartTime))
	fmt.Println(strings.Repeat("=", 60))
}

func main() {
	// Check Xray
	if _, err := os.Stat(XRAYPath); os.IsNotExist(err) {
		fmt.Printf("Error: Xray not found at %s\n", XRAYPath)
		fmt.Println("Please ensure Xray exists at the specified path")
		return
	}

	// Load configs
	configFile := "configs.txt"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	
	fmt.Printf("Loading configs from %s...\n", configFile)
	configURLs, err := loadConfigsFromFile(configFile)
	if err != nil {
		fmt.Printf("Error loading configs: %v\n", err)
		return
	}
	
	if len(configURLs) == 0 {
		fmt.Printf("No configs found in %s\n", configFile)
		fmt.Println("Please add trojan:// or vless:// URLs (one per line)")
		return
	}
	
	fmt.Printf("Loaded %d configs\n", len(configURLs))
	
	// Parse configs
	var configs []*ProxyConfig
	for _, urlStr := range configURLs {
		config, err := ParseProxyURL(urlStr)
		if err != nil {
			fmt.Printf("Failed to parse: %s | Error: %v\n", urlStr[:min(50, len(urlStr))], err)
			continue
		}
		configs = append(configs, config)
	}
	
	if len(configs) == 0 {
		fmt.Println("No valid configs found")
		return
	}
	
	fmt.Printf("Parsed %d valid configs (%d trojan, %d vless)\n", 
		len(configs),
		countProtocol(configs, "trojan"),
		countProtocol(configs, "vless"))
	
	// Setup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	stats = ResultStats{
		StartTime: time.Now(),
	}
	
	configChan := make(chan *ProxyConfig, len(configs))
	resultsChan := make(chan *TestResult, len(configs))
	
	// Start workers
	var wg sync.WaitGroup
	portBase := 11080
	
	for i := 0; i < WorkerCount; i++ {
		wg.Add(1)
		go worker(ctx, configChan, resultsChan, portBase+i*10, &wg)
	}
	
	// Send configs
	go func() {
		for _, config := range configs {
			select {
			case configChan <- config:
			case <-ctx.Done():
				break
			}
		}
		close(configChan)
	}()
	
	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Display results
	var workingConfigs []*TestResult
	for result := range resultsChan {
		if result.Working {
			workingConfigs = append(workingConfigs, result)
		}
	}
	
	// Report
	printFinalReport()
	
	// Save working configs
	if len(workingConfigs) > 0 {
		outputFile := "working_configs.txt"
		f, err := os.Create(outputFile)
		if err == nil {
			defer f.Close()
			writer := bufio.NewWriter(f)
			fmt.Fprintln(writer, "# Working Proxy Configs")
			fmt.Fprintln(writer, "# Format: Protocol | Address | Latency")
			for _, result := range workingConfigs {
				fmt.Fprintf(writer, "%s | %s | %s | %v\n", 
					strings.ToUpper(result.Config.Protocol),
					result.Config.Address,
					result.Config.RawURL,
					result.Latency)
			}
			writer.Flush()
			fmt.Printf("\n✓ Working configs saved to: %s (%d configs)\n", outputFile, len(workingConfigs))
		}
	} else {
		fmt.Println("\n✗ No working configs found")
	}
}

func countProtocol(configs []*ProxyConfig, protocol string) int {
	count := 0
	for _, c := range configs {
		if c.Protocol == protocol {
			count++
		}
	}
	return count
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}