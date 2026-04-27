package proxypool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const (
	defaultProbeTimeout = 10 * time.Second
	probeURLIPAPI       = "http://ip-api.com/json/?lang=zh-CN"
	probeURLHttpbin     = "http://httpbin.org/ip"
	maxProbeResponse    = 1024 * 1024
)

type ProbeResult struct {
	Success   bool   `json:"success"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Country   string `json:"country,omitempty"`
	City      string `json:"city,omitempty"`
	Region    string `json:"region,omitempty"`
	Message   string `json:"message,omitempty"`
}

type ipAPIResponse struct {
	Query       string `json:"query"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	Status      string `json:"status"`
}

type httpbinResponse struct {
	Origin string `json:"origin"`
}

type HealthChecker struct {
	pool       *Pool
	httpClient *http.Client
	mu         sync.Mutex
	running    bool
	cancel     context.CancelFunc

	CheckInterval time.Duration
	Concurrency   int
}

func NewHealthChecker(pool *Pool) *HealthChecker {
	return &HealthChecker{
		pool:          pool,
		CheckInterval: 5 * time.Minute,
		Concurrency:   16,
	}
}

func (h *HealthChecker) ProbeProxy(ctx context.Context, proxyURL string) (*ProbeResult, error) {
	transport, err := buildProbeTransport(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("build transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   defaultProbeTimeout,
	}

	result, err := h.probeWithURL(ctx, client, probeURLIPAPI, "ip-api")
	if err == nil {
		return result, nil
	}

	log.Debugf("ip-api probe failed for %s: %v, trying httpbin", proxyURL, err)
	result, err = h.probeWithURL(ctx, client, probeURLHttpbin, "httpbin")
	if err == nil {
		return result, nil
	}

	return nil, fmt.Errorf("all probe URLs failed: %w", err)
}

func (h *HealthChecker) probeWithURL(ctx context.Context, client *http.Client, probeURL, parser string) (*ProbeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	latency := time.Since(start).Milliseconds()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeResponse))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	switch parser {
	case "ip-api":
		return parseIPAPIResponse(body, latency)
	case "httpbin":
		return parseHttpbinResponse(body, latency)
	default:
		return nil, fmt.Errorf("unknown parser: %s", parser)
	}
}

func parseIPAPIResponse(body []byte, latency int64) (*ProbeResult, error) {
	var resp ipAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse ip-api response: %w", err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("ip-api query failed: status=%s", resp.Status)
	}
	return &ProbeResult{
		Success:   true,
		LatencyMs: latency,
		ExitIP:    resp.Query,
		Country:   resp.Country,
		City:      resp.City,
		Region:    resp.RegionName,
		Message:   "Proxy is accessible",
	}, nil
}

func parseHttpbinResponse(body []byte, latency int64) (*ProbeResult, error) {
	var resp httpbinResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse httpbin response: %w", err)
	}
	ip := strings.TrimSpace(resp.Origin)
	if ip == "" {
		return nil, fmt.Errorf("empty origin from httpbin")
	}
	if idx := strings.Index(ip, ","); idx >= 0 {
		ip = strings.TrimSpace(ip[:idx])
	}
	return &ProbeResult{
		Success:   true,
		LatencyMs: latency,
		ExitIP:    ip,
		Message:   "Proxy is accessible",
	}, nil
}

func (h *HealthChecker) CheckProxy(ctx context.Context, proxy *Proxy) *ProbeResult {
	proxyURL := proxy.URL()
	result, err := h.ProbeProxy(ctx, proxyURL)
	if err != nil {
		return &ProbeResult{
			Success: false,
			Message: err.Error(),
		}
	}
	return result
}

func (h *HealthChecker) CheckAll(ctx context.Context) map[string]*ProbeResult {
	proxies := h.pool.List()
	results := make(map[string]*ProbeResult, len(proxies))

	sem := make(chan struct{}, h.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p *Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := h.CheckProxy(ctx, p)
			mu.Lock()
			results[p.ID] = result
			mu.Unlock()

			updated := &Proxy{
				ID:        p.ID,
				Protocol:  p.Protocol,
				Host:      p.Host,
				Port:      p.Port,
				Username:  p.Username,
				Password:  p.Password,
				Status:    StatusInactive,
				LatencyMs: result.LatencyMs,
				ExitIP:    result.ExitIP,
				Country:   result.Country,
				LastCheck: time.Now(),
				CreatedAt: p.CreatedAt,
			}
			if result.Success {
				updated.Status = StatusActive
			}
			h.pool.Update(updated)
		}(proxy)
	}

	wg.Wait()
	return results
}

func (h *HealthChecker) Start(ctx context.Context) {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	ctx, h.cancel = context.WithCancel(ctx)
	h.mu.Unlock()

	go func() {
		ticker := time.NewTicker(h.CheckInterval)
		defer ticker.Stop()

		h.CheckAll(ctx)

		for {
			select {
			case <-ctx.Done():
				h.mu.Lock()
				h.running = false
				h.mu.Unlock()
				return
			case <-ticker.C:
				h.CheckAll(ctx)
			}
		}
	}()
}

func (h *HealthChecker) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cancel != nil {
		h.cancel()
	}
	h.running = false
}

func buildProbeTransport(proxyURL string) (*http.Transport, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	switch parsed.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if parsed.User != nil {
			auth = &proxy.Auth{
				User:     parsed.User.Username(),
				Password: "",
			}
			if p, ok := parsed.User.Password(); ok {
				auth.Password = p
			}
		}
		proxyAddr := parsed.Host
		if parsed.Port() == "" {
			proxyAddr = net.JoinHostPort(parsed.Hostname(), "1080")
		}
		dialer, errDial := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
		if errDial != nil {
			return nil, fmt.Errorf("create SOCKS5 dialer: %w", errDial)
		}
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			transport.DialContext = contextDialer.DialContext
		}
	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", parsed.Scheme)
	}

	return transport, nil
}

func buildSOCKS5Dialer(parsed *url.URL) (*net.Dialer, error) {
	return &net.Dialer{
		Timeout: 10 * time.Second,
	}, nil
}
