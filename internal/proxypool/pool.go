package proxypool

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxyStatus string

const (
	StatusActive   ProxyStatus = "active"
	StatusInactive ProxyStatus = "inactive"
	StatusUnknown  ProxyStatus = "unknown"
)

type Proxy struct {
	ID        string      `json:"id"`
	Protocol  string      `json:"protocol"`
	Host      string      `json:"host"`
	Port      int         `json:"port"`
	Username  string      `json:"username,omitempty"`
	Password  string      `json:"password,omitempty"`
	Status    ProxyStatus `json:"status"`
	LatencyMs int64       `json:"latency_ms,omitempty"`
	ExitIP    string      `json:"exit_ip,omitempty"`
	Country   string      `json:"country,omitempty"`
	LastCheck time.Time   `json:"last_check,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
}

func (p *Proxy) URL() string {
	u := &url.URL{
		Scheme: p.Protocol,
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	}
	if p.Username != "" && p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u.String()
}

func (p *Proxy) Key() string {
	return strings.Join([]string{
		strings.TrimSpace(p.Protocol),
		strings.TrimSpace(p.Host),
		strconv.Itoa(p.Port),
		strings.TrimSpace(p.Username),
		strings.TrimSpace(p.Password),
	}, "|")
}

func (p *Proxy) IsActive() bool {
	return p.Status == StatusActive
}

type ProxyWithAccountCount struct {
	Proxy
	AccountCount int `json:"account_count"`
}

type ProxyAssignment struct {
	AuthID  string `json:"auth_id"`
	ProxyID string `json:"proxy_id"`
}

type Pool struct {
	mu          sync.RWMutex
	proxies     map[string]*Proxy
	assignments map[string]string
	order       []string
}

func NewPool() *Pool {
	return &Pool{
		proxies:     make(map[string]*Proxy),
		assignments: make(map[string]string),
		order:       make([]string, 0),
	}
}

func (p *Pool) Add(proxy *Proxy) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := proxy.Key()
	if _, exists := p.proxies[key]; exists {
		return false
	}

	if proxy.ID == "" {
		proxy.ID = generateProxyID(proxy)
	}
	if proxy.CreatedAt.IsZero() {
		proxy.CreatedAt = time.Now()
	}
	if proxy.Status == "" {
		proxy.Status = StatusActive
	}

	p.proxies[key] = proxy
	p.order = append(p.order, key)
	return true
}

func (p *Pool) Get(id string) *Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, proxy := range p.proxies {
		if proxy.ID == id {
			return proxy
		}
	}
	return nil
}

func (p *Pool) GetByKey(key string) *Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.proxies[key]
}

func (p *Pool) List() []*Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*Proxy, 0, len(p.order))
	for _, key := range p.order {
		if proxy, ok := p.proxies[key]; ok {
			result = append(result, proxy)
		}
	}
	return result
}

func (p *Pool) ListActive() []*Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*Proxy, 0)
	for _, key := range p.order {
		if proxy, ok := p.proxies[key]; ok && proxy.IsActive() {
			result = append(result, proxy)
		}
	}
	return result
}

func (p *Pool) Update(proxy *Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := proxy.Key()
	if existing, ok := p.proxies[key]; ok {
		existing.Status = proxy.Status
		existing.LatencyMs = proxy.LatencyMs
		existing.ExitIP = proxy.ExitIP
		existing.Country = proxy.Country
		existing.LastCheck = proxy.LastCheck
	}
}

func (p *Pool) Delete(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	var keyToDelete string
	for key, proxy := range p.proxies {
		if proxy.ID == id {
			keyToDelete = key
			break
		}
	}
	if keyToDelete == "" {
		return false
	}

	delete(p.proxies, keyToDelete)
	for i, k := range p.order {
		if k == keyToDelete {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}

	for authID, proxyID := range p.assignments {
		if proxyID == id {
			delete(p.assignments, authID)
		}
	}

	return true
}

func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

func (p *Pool) ActiveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, proxy := range p.proxies {
		if proxy.IsActive() {
			count++
		}
	}
	return count
}

func (p *Pool) AssignProxy(authID string) *Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()

	if proxyID, ok := p.assignments[authID]; ok {
		for _, proxy := range p.proxies {
			if proxy.ID == proxyID && proxy.IsActive() {
				return proxy
			}
		}
	}

	activeProxies := make([]*Proxy, 0)
	for _, key := range p.order {
		if proxy, ok := p.proxies[key]; ok && proxy.IsActive() {
			activeProxies = append(activeProxies, proxy)
		}
	}

	if len(activeProxies) == 0 {
		return nil
	}

	usageCount := make(map[string]int)
	for _, proxyID := range p.assignments {
		usageCount[proxyID]++
	}

	var selected *Proxy
	minUsage := int(^uint(0) >> 1)
	for _, proxy := range activeProxies {
		count := usageCount[proxy.ID]
		if count < minUsage {
			minUsage = count
			selected = proxy
		}
	}

	if selected != nil {
		p.assignments[authID] = selected.ID
	}

	return selected
}

func (p *Pool) GetAssignment(authID string) *Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	proxyID, ok := p.assignments[authID]
	if !ok {
		return nil
	}
	for _, proxy := range p.proxies {
		if proxy.ID == proxyID {
			return proxy
		}
	}
	return nil
}

func (p *Pool) RemoveAssignment(authID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.assignments, authID)
}

func (p *Pool) GetAssignments() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[string]string, len(p.assignments))
	for k, v := range p.assignments {
		result[k] = v
	}
	return result
}

func (p *Pool) GetProxyAccountCount(proxyID string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, pid := range p.assignments {
		if pid == proxyID {
			count++
		}
	}
	return count
}

func (p *Pool) ListWithAccountCount() []*ProxyWithAccountCount {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ProxyWithAccountCount, 0, len(p.order))
	for _, key := range p.order {
		if proxy, ok := p.proxies[key]; ok {
			count := 0
			for _, pid := range p.assignments {
				if pid == proxy.ID {
					count++
				}
			}
			result = append(result, &ProxyWithAccountCount{
				Proxy:        *proxy,
				AccountCount: count,
			})
		}
	}
	return result
}

func generateProxyID(p *Proxy) string {
	h := fnvHash(p.Key())
	return h
}

func fnvHash(s string) string {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	hash := uint32(offset32)
	for _, c := range s {
		hash ^= uint32(c)
		hash *= prime32
	}
	return strconv.FormatUint(uint64(hash), 36)
}
