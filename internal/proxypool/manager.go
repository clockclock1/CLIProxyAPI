package proxypool

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	globalPool     *Pool
	globalChecker  *HealthChecker
	globalImporter *Importer
	once           sync.Once
)

func Init() {
	once.Do(func() {
		globalPool = NewPool()
		globalChecker = NewHealthChecker(globalPool)
		globalImporter = NewImporter(globalPool, globalChecker)
		log.Info("proxy pool initialized")
	})
}

func GetPool() *Pool {
	if globalPool == nil {
		Init()
	}
	return globalPool
}

func GetChecker() *HealthChecker {
	if globalChecker == nil {
		Init()
	}
	return globalChecker
}

func GetImporter() *Importer {
	if globalImporter == nil {
		Init()
	}
	return globalImporter
}

func StartHealthCheck(ctx context.Context) {
	if globalChecker != nil {
		globalChecker.Start(ctx)
	}
}

func StopHealthCheck() {
	if globalChecker != nil {
		globalChecker.Stop()
	}
}

func AssignProxyForAuth(authID string) string {
	if globalPool == nil {
		return ""
	}
	proxy := globalPool.AssignProxy(authID)
	if proxy == nil {
		return ""
	}
	return proxy.URL()
}

func GetProxyURLForAuth(authID string) string {
	if globalPool == nil {
		return ""
	}
	proxy := globalPool.GetAssignment(authID)
	if proxy == nil {
		return ""
	}
	return proxy.URL()
}
