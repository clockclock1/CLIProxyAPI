package proxypool

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type ImportResult struct {
	Created int      `json:"created"`
	Skipped int      `json:"skipped"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
}

type Importer struct {
	pool     *Pool
	checker  *HealthChecker
	client   *http.Client
	AutoTest bool
}

func NewImporter(pool *Pool, checker *HealthChecker) *Importer {
	return &Importer{
		pool:     pool,
		checker:  checker,
		client:   &http.Client{Timeout: 30 * time.Second},
		AutoTest: true,
	}
}

func (imp *Importer) ImportText(ctx context.Context, text string) *ImportResult {
	result := &ImportResult{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNum := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		proxy, err := parseProxyLine(line)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("line %d: %v", lineNum, err))
			continue
		}

		if imp.pool.GetByKey(proxy.Key()) != nil {
			result.Skipped++
			continue
		}

		if imp.pool.Add(proxy) {
			result.Created++
			if imp.AutoTest && imp.checker != nil {
				go imp.testProxy(proxy)
			}
		} else {
			result.Skipped++
		}
	}

	return result
}

func (imp *Importer) ImportURL(ctx context.Context, rawURL string) *ImportResult {
	result := &ImportResult{}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Sprintf("create request: %v", err))
		return result
	}
	req.Header.Set("User-Agent", "CLIProxyAPI/1.0")

	resp, err := imp.client.Do(req)
	if err != nil {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Sprintf("fetch URL: %v", err))
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Sprintf("HTTP %d", resp.StatusCode))
		return result
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return imp.importJSONResponse(ctx, resp.Body)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Sprintf("read body: %v", err))
		return result
	}

	return imp.ImportText(ctx, string(body))
}

func (imp *Importer) importJSONResponse(ctx context.Context, body io.Reader) *ImportResult {
	result := &ImportResult{}

	bodyBytes, err := io.ReadAll(io.LimitReader(body, 10*1024*1024))
	if err != nil {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Sprintf("read body: %v", err))
		return result
	}

	var data struct {
		Data []struct {
			Host     string `json:"host"`
			Port     any    `json:"port"`
			Protocol string `json:"protocol"`
			Username string `json:"username"`
			Password string `json:"password"`
			Type     string `json:"type"`
			Address  string `json:"address"`
		} `json:"data"`
		Proxies []struct {
			Host     string `json:"host"`
			Port     any    `json:"port"`
			Protocol string `json:"protocol"`
			Username string `json:"username"`
			Password string `json:"password"`
			Type     string `json:"type"`
			Address  string `json:"address"`
		} `json:"proxies"`
	}

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return imp.ImportText(ctx, string(bodyBytes))
	}

	items := data.Data
	if len(items) == 0 {
		items = data.Proxies
	}

	for i, item := range items {
		proxy, err := parseJSONProxyItem(item)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("item %d: %v", i, err))
			continue
		}

		if imp.pool.GetByKey(proxy.Key()) != nil {
			result.Skipped++
			continue
		}

		if imp.pool.Add(proxy) {
			result.Created++
			if imp.AutoTest && imp.checker != nil {
				go imp.testProxy(proxy)
			}
		} else {
			result.Skipped++
		}
	}

	return result
}

func (imp *Importer) testProxy(proxy *Proxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := imp.checker.CheckProxy(ctx, proxy)
	updated := &Proxy{
		ID:        proxy.ID,
		Protocol:  proxy.Protocol,
		Host:      proxy.Host,
		Port:      proxy.Port,
		Username:  proxy.Username,
		Password:  proxy.Password,
		Status:    StatusInactive,
		LatencyMs: result.LatencyMs,
		ExitIP:    result.ExitIP,
		Country:   result.Country,
		LastCheck: time.Now(),
		CreatedAt: proxy.CreatedAt,
	}
	if result.Success {
		updated.Status = StatusActive
	}
	imp.pool.Update(updated)

	if result.Success {
		log.Debugf("proxy %s test passed: latency=%dms exit_ip=%s", proxy.URL(), result.LatencyMs, result.ExitIP)
	} else {
		log.Debugf("proxy %s test failed: %s", proxy.URL(), result.Message)
	}
}

func parseProxyLine(line string) (*Proxy, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	if strings.Contains(line, "://") {
		return parseProxyURL(line)
	}

	parts := strings.Split(line, ":")
	switch len(parts) {
	case 2:
		host := strings.TrimSpace(parts[0])
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", parts[1])
		}
		return &Proxy{Protocol: "socks5", Host: host, Port: port}, nil
	case 3:
		protocol := strings.TrimSpace(parts[0])
		host := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", parts[2])
		}
		return &Proxy{Protocol: protocol, Host: host, Port: port}, nil
	case 4:
		host := strings.TrimSpace(parts[0])
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", parts[1])
		}
		return &Proxy{
			Protocol: "socks5", Host: host, Port: port,
			Username: strings.TrimSpace(parts[2]),
			Password: strings.TrimSpace(parts[3]),
		}, nil
	case 5:
		protocol := strings.TrimSpace(parts[0])
		host := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", parts[2])
		}
		return &Proxy{
			Protocol: protocol, Host: host, Port: port,
			Username: strings.TrimSpace(parts[3]),
			Password: strings.TrimSpace(parts[4]),
		}, nil
	default:
		return nil, fmt.Errorf("invalid format: %s", line)
	}
}

func parseProxyURL(rawURL string) (*Proxy, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	protocol := parsed.Scheme
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in URL: %s", rawURL)
	}

	portStr := parsed.Port()
	var port int
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
	} else {
		switch protocol {
		case "http":
			port = 80
		case "https":
			port = 443
		case "socks5", "socks5h":
			port = 1080
		default:
			port = 1080
		}
	}

	var username, password string
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}

	return &Proxy{
		Protocol: protocol,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

func parseJSONProxyItem(item struct {
	Host     string `json:"host"`
	Port     any    `json:"port"`
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	Password string `json:"password"`
	Type     string `json:"type"`
	Address  string `json:"address"`
}) (*Proxy, error) {
	protocol := strings.TrimSpace(item.Protocol)
	if protocol == "" {
		protocol = strings.TrimSpace(item.Type)
	}
	if protocol == "" {
		protocol = "socks5"
	}

	host := strings.TrimSpace(item.Host)
	if host == "" {
		host = strings.TrimSpace(item.Address)
	}
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}

	var port int
	switch v := item.Port.(type) {
	case float64:
		port = int(v)
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %v", item.Port)
		}
		port = p
	case nil:
		switch protocol {
		case "http":
			port = 80
		case "https":
			port = 443
		default:
			port = 1080
		}
	default:
		return nil, fmt.Errorf("invalid port type: %T", item.Port)
	}

	return &Proxy{
		Protocol: protocol,
		Host:     host,
		Port:     port,
		Username: strings.TrimSpace(item.Username),
		Password: strings.TrimSpace(item.Password),
	}, nil
}
