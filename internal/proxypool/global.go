package proxypool

import (
	"strings"
	"sync"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

var (
	globalPool     *ProxyPool
	globalPoolMu   sync.RWMutex
	accountMapping map[string]string
	mapMu          sync.RWMutex
)

func InitGlobalPool(cfg PoolConfig) {
	globalPoolMu.Lock()
	defer globalPoolMu.Unlock()
	if globalPool != nil {
		globalPool.Stop()
	}
	globalPool = NewProxyPool(cfg)
	accountMapping = make(map[string]string)

	for _, u := range cfg.ImportURLs {
		if strings.TrimSpace(u) != "" {
			go func(url string) {
				n, err := globalPool.ImportFromURL(url)
				if err == nil && n > 0 {
					return
				}
			}(u)
		}
	}

	if len(cfg.ProxyList) > 0 || len(cfg.ImportURLs) > 0 {
		globalPool.StartHealthCheck()
	}
}

func GetGlobalPool() *ProxyPool {
	globalPoolMu.RLock()
	defer globalPoolMu.RUnlock()
	return globalPool
}

func AssignProxyToAuth(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if proxyURL := strings.TrimSpace(auth.ProxyURL); proxyURL != "" {
		return proxyURL
	}

	pool := GetGlobalPool()
	if pool == nil {
		return ""
	}

	accountID := auth.ID
	if accountID == "" {
		accountID = auth.EnsureIndex()
	}

	mapMu.Lock()
	defer mapMu.Unlock()

	if mapped, ok := accountMapping[accountID]; ok {
		alive := pool.Alive()
		for _, e := range alive {
			if e.URL == mapped {
				return mapped
			}
		}
	}

	entry := pool.AssignToAccount(accountID)
	if entry == nil {
		return ""
	}

	accountMapping[accountID] = entry.URL
	return entry.URL
}

func GetAccountProxy(accountID string) string {
	if accountID == "" {
		return ""
	}
	mapMu.RLock()
	defer mapMu.RUnlock()
	return accountMapping[accountID]
}

func RebuildAccountMappings() {
	pool := GetGlobalPool()
	if pool == nil {
		return
	}
	alive := pool.Alive()
	if len(alive) == 0 {
		return
	}

	mapMu.Lock()
	defer mapMu.Unlock()

	for accountID := range accountMapping {
		entry := pool.AssignToAccount(accountID)
		if entry != nil {
			accountMapping[accountID] = entry.URL
		}
	}
}

func StopGlobalPool() {
	globalPoolMu.Lock()
	defer globalPoolMu.Unlock()
	if globalPool != nil {
		globalPool.Stop()
		globalPool = nil
	}
}
