package management

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/proxypool"
)

type ProxyPoolHandler struct {
	pool     *proxypool.Pool
	checker  *proxypool.HealthChecker
	importer *proxypool.Importer
}

func NewProxyPoolHandler(pool *proxypool.Pool, checker *proxypool.HealthChecker, importer *proxypool.Importer) *ProxyPoolHandler {
	return &ProxyPoolHandler{
		pool:     pool,
		checker:  checker,
		importer: importer,
	}
}

func (h *ProxyPoolHandler) ListProxies(c *gin.Context) {
	withCount := c.Query("with_count") == "true"
	if withCount {
		proxies := h.pool.ListWithAccountCount()
		c.JSON(http.StatusOK, gin.H{"proxies": proxies, "total": len(proxies)})
		return
	}
	proxies := h.pool.List()
	c.JSON(http.StatusOK, gin.H{"proxies": proxies, "total": len(proxies)})
}

func (h *ProxyPoolHandler) GetProxy(c *gin.Context) {
	id := c.Param("id")
	proxy := h.pool.Get(id)
	if proxy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}
	c.JSON(http.StatusOK, proxy)
}

type createProxyRequest struct {
	Protocol string `json:"protocol" binding:"required,oneof=http https socks5 socks5h"`
	Host     string `json:"host" binding:"required"`
	Port     int    `json:"port" binding:"required,min=1,max=65535"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *ProxyPoolHandler) CreateProxy(c *gin.Context) {
	var req createProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	proxy := &proxypool.Proxy{
		Protocol: strings.TrimSpace(req.Protocol),
		Host:     strings.TrimSpace(req.Host),
		Port:     req.Port,
		Username: strings.TrimSpace(req.Username),
		Password: strings.TrimSpace(req.Password),
	}

	if h.pool.GetByKey(proxy.Key()) != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "proxy already exists"})
		return
	}

	if !h.pool.Add(proxy) {
		c.JSON(http.StatusConflict, gin.H{"error": "proxy already exists"})
		return
	}

	if h.checker != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			result := h.checker.CheckProxy(ctx, proxy)
			updated := &proxypool.Proxy{
				ID:        proxy.ID,
				Protocol:  proxy.Protocol,
				Host:      proxy.Host,
				Port:      proxy.Port,
				Username:  proxy.Username,
				Password:  proxy.Password,
				Status:    proxypool.StatusInactive,
				LatencyMs: result.LatencyMs,
				ExitIP:    result.ExitIP,
				Country:   result.Country,
				LastCheck: time.Now(),
				CreatedAt: proxy.CreatedAt,
			}
			if result.Success {
				updated.Status = proxypool.StatusActive
			}
			h.pool.Update(updated)
		}()
	}

	c.JSON(http.StatusCreated, proxy)
}

func (h *ProxyPoolHandler) DeleteProxy(c *gin.Context) {
	id := c.Param("id")
	if !h.pool.Delete(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "proxy deleted"})
}

type batchDeleteRequest struct {
	IDs []string `json:"ids" binding:"required,min=1"`
}

func (h *ProxyPoolHandler) BatchDeleteProxies(c *gin.Context) {
	var req batchDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deleted := 0
	for _, id := range req.IDs {
		if h.pool.Delete(id) {
			deleted++
		}
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func (h *ProxyPoolHandler) TestProxy(c *gin.Context) {
	id := c.Param("id")
	proxy := h.pool.Get(id)
	if proxy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	result := h.checker.CheckProxy(ctx, proxy)

	updated := &proxypool.Proxy{
		ID:        proxy.ID,
		Protocol:  proxy.Protocol,
		Host:      proxy.Host,
		Port:      proxy.Port,
		Username:  proxy.Username,
		Password:  proxy.Password,
		Status:    proxypool.StatusInactive,
		LatencyMs: result.LatencyMs,
		ExitIP:    result.ExitIP,
		Country:   result.Country,
		LastCheck: time.Now(),
		CreatedAt: proxy.CreatedAt,
	}
	if result.Success {
		updated.Status = proxypool.StatusActive
	}
	h.pool.Update(updated)

	c.JSON(http.StatusOK, result)
}

func (h *ProxyPoolHandler) TestAllProxies(c *gin.Context) {
	results := h.checker.CheckAll(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
	})
}

type importTextRequest struct {
	Text     string `json:"text" binding:"required"`
	AutoTest *bool  `json:"auto_test"`
}

func (h *ProxyPoolHandler) ImportText(c *gin.Context) {
	var req importTextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.AutoTest != nil {
		h.importer.AutoTest = *req.AutoTest
	} else {
		h.importer.AutoTest = true
	}

	result := h.importer.ImportText(c.Request.Context(), req.Text)
	c.JSON(http.StatusOK, result)
}

type importURLRequest struct {
	URL      string `json:"url" binding:"required"`
	AutoTest *bool  `json:"auto_test"`
}

func (h *ProxyPoolHandler) ImportURL(c *gin.Context) {
	var req importURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.AutoTest != nil {
		h.importer.AutoTest = *req.AutoTest
	} else {
		h.importer.AutoTest = true
	}

	result := h.importer.ImportURL(c.Request.Context(), req.URL)
	c.JSON(http.StatusOK, result)
}

type assignProxyRequest struct {
	AuthID string `json:"auth_id" binding:"required"`
}

func (h *ProxyPoolHandler) AssignProxy(c *gin.Context) {
	var req assignProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	proxy := h.pool.AssignProxy(req.AuthID)
	if proxy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active proxies available"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"auth_id": req.AuthID, "proxy": proxy})
}

func (h *ProxyPoolHandler) GetAssignment(c *gin.Context) {
	authID := c.Param("auth_id")
	proxy := h.pool.GetAssignment(authID)
	if proxy == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no proxy assigned"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"auth_id": authID, "proxy": proxy})
}

func (h *ProxyPoolHandler) RemoveAssignment(c *gin.Context) {
	authID := c.Param("auth_id")
	h.pool.RemoveAssignment(authID)
	c.JSON(http.StatusOK, gin.H{"message": "assignment removed"})
}

func (h *ProxyPoolHandler) GetAssignments(c *gin.Context) {
	assignments := h.pool.GetAssignments()
	c.JSON(http.StatusOK, gin.H{"assignments": assignments, "total": len(assignments)})
}

func (h *ProxyPoolHandler) AutoAssignAll(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "auto-assign is handled automatically when accounts request proxies"})
}

func (h *ProxyPoolHandler) GetStats(c *gin.Context) {
	total := h.pool.Count()
	active := h.pool.ActiveCount()
	assignments := h.pool.GetAssignments()

	avgLatency := int64(0)
	proxies := h.pool.List()
	activeCount := 0
	for _, p := range proxies {
		if p.IsActive() && p.LatencyMs > 0 {
			avgLatency += p.LatencyMs
			activeCount++
		}
	}
	if activeCount > 0 {
		avgLatency /= int64(activeCount)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_proxies":     total,
		"active_proxies":    active,
		"inactive_proxies":  total - active,
		"total_assignments": len(assignments),
		"avg_latency_ms":    avgLatency,
	})
}

func (h *ProxyPoolHandler) StartHealthCheck(c *gin.Context) {
	intervalStr := c.DefaultQuery("interval", "300")
	interval, err := strconv.Atoi(intervalStr)
	if err != nil || interval < 30 {
		interval = 300
	}
	h.checker.CheckInterval = time.Duration(interval) * time.Second
	h.checker.Start(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"message": "health checker started", "interval_seconds": interval})
}

func (h *ProxyPoolHandler) StopHealthCheck(c *gin.Context) {
	h.checker.Stop()
	c.JSON(http.StatusOK, gin.H{"message": "health checker stopped"})
}
