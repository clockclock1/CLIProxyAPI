package proxypool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	"golang.org/x/net/proxy"
)

type ProxyStatus string

const (
	StatusUnknown  ProxyStatus = "unknown"
	StatusAlive    ProxyStatus = "alive"
	StatusDead     ProxyStatus = "dead"
	StatusChecking ProxyStatus = "checking"
)

type ProxyEntry struct {
	URL       string        `json:"url"`
	Protocol  string        `json:"protocol"`
	Host      string        `json:"host"`
	Port      string        `json:"port"`
	Username  string        `json:"username,omitempty"`
	Password  string        `json:"password,omitempty"`
	Status    ProxyStatus   `json:"status"`
	LastCheck time.Time     `json:"last_check,omitempty"`
	Latency   time.Duration `json:"latency,omitempty"`
	FailCount int           `json:"fail_count"`
	mu        sync.RWMutex
}

func (e *ProxyEntry) SetStatus(s ProxyStatus) {
	e.mu.Lock()
	e.Status = s
	e.LastCheck = time.Now()
	e.mu.Unlock()
}

func (e *ProxyEntry) GetStatus() ProxyStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Status
}

func (e *ProxyEntry) Key() string {
	return strings.ToLower(e.Protocol) + "|" + e.Host + "|" + e.Port + "|" + e.Username + "|" + e.Password
}

func ParseProxyURL(raw string) (*ProxyEntry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	if !strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, ":", 4)
		switch len(parts) {
		case 2:
			raw = "socks5h://" + parts[0] + ":" + parts[1]
		case 3:
			raw = "socks5h://" + parts[0] + ":" + parts[1] + ":" + parts[2]
		case 4:
			raw = "socks5h://" + parts[2] + ":" + parts[3] + "@" + parts[0] + ":" + parts[1]
		}
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "socks5" {
		scheme = "socks5h"
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch scheme {
		case "http", "https":
			port = "80"
		case "socks5h":
			port = "1080"
		}
	}

	var username, password string
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}

	return &ProxyEntry{
		URL:      raw,
		Protocol: scheme,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Status:   StatusUnknown,
	}, nil
}

type ProxyPool struct {
	entries  map[string]*ProxyEntry
	order    []string
	mu       sync.RWMutex
	robinIdx atomic.Int64
	checkURL string
	checkInt time.Duration
	timeout  time.Duration
	maxFail  int
	stopCh   chan struct{}
	wg       sync.WaitGroup
	onChange func()
}

type PoolConfig struct {
	CheckURL      string        `yaml:"check-url" json:"check-url"`
	CheckInterval time.Duration `yaml:"check-interval" json:"check-interval"`
	CheckTimeout  time.Duration `yaml:"check-timeout" json:"check-timeout"`
	MaxFailCount  int           `yaml:"max-fail-count" json:"max-fail-count"`
	ImportURLs    []string      `yaml:"import-urls" json:"import-urls"`
	ProxyList     []string      `yaml:"proxy-list" json:"proxy-list"`
}

func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		CheckURL:      "https://cloudflare.com/cdn-cgi/trace",
		CheckInterval: 5 * time.Minute,
		CheckTimeout:  10 * time.Second,
		MaxFailCount:  3,
	}
}

func NewProxyPool(cfg PoolConfig) *ProxyPool {
	p := &ProxyPool{
		entries:  make(map[string]*ProxyEntry),
		checkURL: cfg.CheckURL,
		checkInt: cfg.CheckInterval,
		timeout:  cfg.CheckTimeout,
		maxFail:  cfg.MaxFailCount,
		stopCh:   make(chan struct{}),
	}

	if len(cfg.ProxyList) > 0 {
		p.ImportBatch(cfg.ProxyList)
	}

	return p
}

func (p *ProxyPool) SetOnChange(fn func()) {
	p.mu.Lock()
	p.onChange = fn
	p.mu.Unlock()
}

func (p *ProxyPool) ImportBatch(lines []string) (added int) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := ParseProxyURL(line)
		if err != nil || entry == nil {
			continue
		}
		if p.addEntry(entry) {
			added++
		}
	}
	return added
}

func (p *ProxyPool) addEntry(entry *ProxyEntry) bool {
	key := entry.Key()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.entries[key]; exists {
		return false
	}
	p.entries[key] = entry
	p.order = append(p.order, key)
	return true
}

func (p *ProxyPool) RemoveEntry(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, key)
	for i, k := range p.order {
		if k == key {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
}

func (p *ProxyPool) All() []*ProxyEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*ProxyEntry, 0, len(p.order))
	for _, key := range p.order {
		if e, ok := p.entries[key]; ok {
			out = append(out, e)
		}
	}
	return out
}

func (p *ProxyPool) Alive() []*ProxyEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*ProxyEntry, 0, len(p.order))
	for _, key := range p.order {
		if e, ok := p.entries[key]; ok && e.GetStatus() == StatusAlive {
			out = append(out, e)
		}
	}
	return out
}

func (p *ProxyPool) Count() (total int, alive int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total = len(p.entries)
	for _, e := range p.entries {
		if e.GetStatus() == StatusAlive {
			alive++
		}
	}
	return
}

func (p *ProxyPool) Assign() *ProxyEntry {
	alive := p.Alive()
	if len(alive) == 0 {
		return nil
	}
	idx := p.robinIdx.Add(1) % int64(len(alive))
	return alive[idx]
}

func (p *ProxyPool) AssignToAccount(accountID string) *ProxyEntry {
	if accountID == "" {
		return p.Assign()
	}
	alive := p.Alive()
	if len(alive) == 0 {
		return nil
	}
	hash := fnvHash(accountID)
	idx := hash % uint64(len(alive))
	return alive[idx]
}

func fnvHash(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, c := range s {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

func (p *ProxyPool) StartHealthCheck() {
	if p.checkInt <= 0 {
		p.checkInt = 5 * time.Minute
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.checkAll()
		ticker := time.NewTicker(p.checkInt)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.checkAll()
			case <-p.stopCh:
				return
			}
		}
	}()
}

func (p *ProxyPool) Stop() {
	close(p.stopCh)
	p.wg.Wait()
}

func (p *ProxyPool) checkAll() {
	entries := p.All()
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		sem <- struct{}{}
		go func(entry *ProxyEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			p.checkOne(entry)
		}(e)
	}
	wg.Wait()

	p.mu.RLock()
	fn := p.onChange
	p.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func (p *ProxyPool) checkOne(entry *ProxyEntry) {
	entry.mu.Lock()
	entry.Status = StatusChecking
	entry.mu.Unlock()

	client := buildCheckClient(entry.URL, p.timeout)
	start := time.Now()
	resp, err := client.Get(p.checkURL)
	latency := time.Since(start)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if err != nil {
		entry.FailCount++
		if entry.FailCount >= p.maxFail {
			entry.Status = StatusDead
		}
		entry.Latency = 0
		entry.LastCheck = time.Now()
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		entry.Status = StatusAlive
		entry.FailCount = 0
		entry.Latency = latency
	} else {
		entry.FailCount++
		if entry.FailCount >= p.maxFail {
			entry.Status = StatusDead
		}
	}
	entry.LastCheck = time.Now()
}

func buildCheckClient(proxyURL string, timeout time.Duration) *http.Client {
	transport, mode, err := proxyutil.BuildHTTPTransport(proxyURL)
	if err != nil || mode == proxyutil.ModeInherit || transport == nil {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		if mode == proxyutil.ModeProxy {
			setting, _ := proxyutil.Parse(proxyURL)
			if setting.URL.Scheme == "socks5" || setting.URL.Scheme == "socks5h" {
				var proxyAuth *proxy.Auth
				if setting.URL.User != nil {
					username := setting.URL.User.Username()
					password, _ := setting.URL.User.Password()
					proxyAuth = &proxy.Auth{User: username, Password: password}
				}
				dialer, _ := proxy.SOCKS5("tcp", setting.URL.Host, proxyAuth, proxy.Direct)
				transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			} else {
				transport.Proxy = http.ProxyURL(setting.URL)
			}
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func (p *ProxyPool) ImportFromURL(rawURL string) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, fmt.Errorf("fetch proxy URL failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read proxy URL response failed: %w", err)
	}

	var proxies []string

	var data struct {
		Data []struct {
			Protocol string `json:"protocol"`
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err == nil && len(data.Data) > 0 {
		for _, d := range data.Data {
			proto := d.Protocol
			if proto == "" {
				proto = "socks5h"
			}
			u := url.URL{
				Scheme: proto,
				Host:   net.JoinHostPort(d.Host, strconv.Itoa(d.Port)),
			}
			if d.Username != "" {
				u.User = url.UserPassword(d.Username, d.Password)
			}
			proxies = append(proxies, u.String())
		}
	} else {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				proxies = append(proxies, line)
			}
		}
	}

	return p.ImportBatch(proxies), nil
}
