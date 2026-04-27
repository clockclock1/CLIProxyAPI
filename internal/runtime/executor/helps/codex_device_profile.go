package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const (
	codexDeviceProfileTTL           = 7 * 24 * time.Hour
	codexDeviceProfileCleanupPeriod = time.Hour
)

var (
	codexTUIVersionPattern = regexp.MustCompile(`^codex[_-](tui|cli_rs)/(\d+)\.(\d+)\.(\d+)`)

	codexDeviceProfileCache            = make(map[string]codexDeviceProfileCacheEntry)
	codexDeviceProfileCacheMu          sync.RWMutex
	codexDeviceProfileCacheCleanupOnce sync.Once
)

type codexCLIVersion struct {
	major int
	minor int
	patch int
}

func (v codexCLIVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

type CodexDeviceProfile struct {
	ClientType    string
	Version       codexCLIVersion
	OS            string
	OSVersion     string
	Arch          string
	Terminal      string
	TerminalVer   string
	UserAgent     string
	Originator    string
	BetaFeatures  string
	HasVersion    bool
}

func (p CodexDeviceProfile) VersionString() string {
	if !p.HasVersion {
		return ""
	}
	return p.Version.String()
}

type codexDeviceProfileCacheEntry struct {
	profile CodexDeviceProfile
	expire  time.Time
}

var (
	codexOSOptions = []struct {
		Name    string
		Version string
		Arch    string
	}{
		{"Mac OS", "14.2.0", "x86_64"},
		{"Mac OS", "14.3.1", "arm64"},
		{"Mac OS", "14.5.0", "arm64"},
		{"Mac OS", "14.6.1", "x86_64"},
		{"Mac OS", "15.0.0", "arm64"},
		{"Mac OS", "15.1.0", "arm64"},
		{"Mac OS", "15.2.0", "x86_64"},
		{"Mac OS", "15.3.0", "arm64"},
		{"Mac OS", "26.3.1", "arm64"},
		{"Mac OS", "26.2.0", "x86_64"},
		{"Linux", "6.1.0", "x86_64"},
		{"Linux", "6.5.0", "x86_64"},
		{"Linux", "6.8.0", "aarch64"},
		{"Linux", "5.15.0", "x86_64"},
		{"Windows", "10.0", "x86_64"},
		{"Windows", "11.0", "x86_64"},
	}

	codexTerminalOptions = []struct {
		Name string
		Ver  string
	}{
		{"iTerm.app", "3.6.9"},
		{"iTerm.app", "3.5.7"},
		{"Terminal.app", "455"},
		{"vscode", "1.111.0"},
		{"vscode", "1.110.0"},
		{"vscode", "1.109.0"},
		{"vscode-insiders", "1.112.0"},
		{"cursor", "0.50.7"},
		{"cursor", "0.49.0"},
		{"warp", "0.2025.01.15"},
		{"alacritty", "0.14.0"},
		{"kitty", "0.38.1"},
		{"gnome-terminal", "3.52.0"},
		{"konsole", "24.12.2"},
		{"Windows Terminal", "1.22.0"},
	}

	codexVersionOptions = []codexCLIVersion{
		{0, 114, 0},
		{0, 115, 0},
		{0, 116, 0},
		{0, 117, 0},
		{0, 118, 0},
		{0, 119, 0},
		{0, 120, 0},
	}

	codexBetaFeaturesOptions = []string{
		"multi_agent",
		"multi_agent,code_search",
		"multi_agent,sandbox",
		"multi_agent,code_search,sandbox",
		"",
	}
)

func generateCodexDeviceProfile(authID string) CodexDeviceProfile {
	seed := sha256.Sum256([]byte(authID))
	var seedInt int64
	for i := 0; i < 8; i++ {
		seedInt = seedInt*31 + int64(seed[i])
	}
	r := rand.New(rand.NewSource(seedInt))

	osIdx := r.Intn(len(codexOSOptions))
	termIdx := r.Intn(len(codexTerminalOptions))
	verIdx := r.Intn(len(codexVersionOptions))
	betaIdx := r.Intn(len(codexBetaFeaturesOptions))

	clientType := "codex-tui"
	if r.Float64() < 0.3 {
		clientType = "codex_cli_rs"
	}

	osOpt := codexOSOptions[osIdx]
	termOpt := codexTerminalOptions[termIdx]
	verOpt := codexVersionOptions[verIdx]
	betaOpt := codexBetaFeaturesOptions[betaIdx]

	var userAgent string
	if clientType == "codex-tui" {
		userAgent = fmt.Sprintf("codex-tui/%s (%s %s; %s) %s/%s (codex-tui; %s)",
			verOpt.String(), osOpt.Name, osOpt.Version, osOpt.Arch,
			termOpt.Name, termOpt.Ver, verOpt.String())
	} else {
		userAgent = fmt.Sprintf("codex_cli_rs/%s (%s %s; %s) %s/%s",
			verOpt.String(), osOpt.Name, osOpt.Version, osOpt.Arch,
			termOpt.Name, termOpt.Ver)
	}

	return CodexDeviceProfile{
		ClientType:   clientType,
		Version:      verOpt,
		OS:           osOpt.Name,
		OSVersion:    osOpt.Version,
		Arch:         osOpt.Arch,
		Terminal:     termOpt.Name,
		TerminalVer:  termOpt.Ver,
		UserAgent:    userAgent,
		Originator:   clientType,
		BetaFeatures: betaOpt,
		HasVersion:   true,
	}
}

func codexDeviceProfileCacheKey(auth *cliproxyauth.Auth, apiKey string) string {
	scope := "global"
	switch {
	case auth != nil && strings.TrimSpace(auth.ID) != "":
		scope = "auth:" + strings.TrimSpace(auth.ID)
	case strings.TrimSpace(apiKey) != "":
		scope = "api_key:" + strings.TrimSpace(apiKey)
	}
	sum := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(sum[:])
}

func startCodexDeviceProfileCacheCleanup() {
	go func() {
		ticker := time.NewTicker(codexDeviceProfileCleanupPeriod)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredCodexDeviceProfiles()
		}
	}()
}

func purgeExpiredCodexDeviceProfiles() {
	now := time.Now()
	codexDeviceProfileCacheMu.Lock()
	for key, entry := range codexDeviceProfileCache {
		if !entry.expire.After(now) {
			delete(codexDeviceProfileCache, key)
		}
	}
	codexDeviceProfileCacheMu.Unlock()
}

func ResolveCodexDeviceProfile(auth *cliproxyauth.Auth, apiKey string, headers http.Header, cfg *config.Config) CodexDeviceProfile {
	codexDeviceProfileCacheCleanupOnce.Do(startCodexDeviceProfileCacheCleanup)

	cacheKey := codexDeviceProfileCacheKey(auth, apiKey)
	now := time.Now()

	codexDeviceProfileCacheMu.RLock()
	entry, hasCached := codexDeviceProfileCache[cacheKey]
	cachedValid := hasCached && entry.expire.After(now) && entry.profile.UserAgent != ""
	codexDeviceProfileCacheMu.RUnlock()

	if cachedValid {
		codexDeviceProfileCacheMu.Lock()
		entry.expire = now.Add(codexDeviceProfileTTL)
		codexDeviceProfileCache[cacheKey] = entry
		codexDeviceProfileCacheMu.Unlock()
		return entry.profile
	}

	clientProfile := extractCodexDeviceProfileFromHeaders(headers)
	if clientProfile != nil {
		codexDeviceProfileCacheMu.Lock()
		codexDeviceProfileCache[cacheKey] = codexDeviceProfileCacheEntry{
			profile: *clientProfile,
			expire:  now.Add(codexDeviceProfileTTL),
		}
		codexDeviceProfileCacheMu.Unlock()
		return *clientProfile
	}

	if cfg != nil && strings.TrimSpace(cfg.CodexHeaderDefaults.UserAgent) != "" {
		profile := buildCodexProfileFromConfig(cfg)
		codexDeviceProfileCacheMu.Lock()
		codexDeviceProfileCache[cacheKey] = codexDeviceProfileCacheEntry{
			profile: profile,
			expire:  now.Add(codexDeviceProfileTTL),
		}
		codexDeviceProfileCacheMu.Unlock()
		return profile
	}

	accountID := "global"
	if auth != nil {
		accountID = auth.ID
		if accountID == "" {
			accountID = auth.EnsureIndex()
		}
	}
	profile := generateCodexDeviceProfile(accountID)

	codexDeviceProfileCacheMu.Lock()
	codexDeviceProfileCache[cacheKey] = codexDeviceProfileCacheEntry{
		profile: profile,
		expire:  now.Add(codexDeviceProfileTTL),
	}
	codexDeviceProfileCacheMu.Unlock()

	return profile
}

func extractCodexDeviceProfileFromHeaders(headers http.Header) *CodexDeviceProfile {
	if headers == nil {
		return nil
	}
	ua := strings.TrimSpace(headers.Get("User-Agent"))
	if ua == "" {
		return nil
	}
	matches := codexTUIVersionPattern.FindStringSubmatch(ua)
	if len(matches) < 5 {
		return nil
	}

	var major, minor, patch int
	fmt.Sscanf(matches[2], "%d", &major)
	fmt.Sscanf(matches[3], "%d", &minor)
	fmt.Sscanf(matches[4], "%d", &patch)

	clientType := "codex-tui"
	if matches[1] == "cli_rs" {
		clientType = "codex_cli_rs"
	}

	profile := &CodexDeviceProfile{
		ClientType: clientType,
		Version: codexCLIVersion{
			major: major,
			minor: minor,
			patch: patch,
		},
		UserAgent:   ua,
		Originator:  clientType,
		HasVersion:  true,
	}

	if beta := strings.TrimSpace(headers.Get("X-Codex-Beta-Features")); beta != "" {
		profile.BetaFeatures = beta
	}

	return profile
}

func buildCodexProfileFromConfig(cfg *config.Config) CodexDeviceProfile {
	ua := strings.TrimSpace(cfg.CodexHeaderDefaults.UserAgent)
	profile := CodexDeviceProfile{
		UserAgent:    ua,
		Originator:   "codex-tui",
		BetaFeatures: strings.TrimSpace(cfg.CodexHeaderDefaults.BetaFeatures),
	}

	matches := codexTUIVersionPattern.FindStringSubmatch(ua)
	if len(matches) >= 5 {
		clientType := "codex-tui"
		if matches[1] == "cli_rs" {
			clientType = "codex_cli_rs"
		}
		profile.ClientType = clientType
		profile.Originator = clientType
		var major, minor, patch int
		fmt.Sscanf(matches[2], "%d", &major)
		fmt.Sscanf(matches[3], "%d", &minor)
		fmt.Sscanf(matches[4], "%d", &patch)
		profile.Version = codexCLIVersion{major: major, minor: minor, patch: patch}
		profile.HasVersion = true
	}

	return profile
}

func ApplyCodexDeviceProfileHeaders(r *http.Request, profile CodexDeviceProfile) {
	if r == nil {
		return
	}

	if profile.UserAgent != "" {
		r.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.Originator != "" {
		r.Header.Set("Originator", profile.Originator)
	}
	if profile.BetaFeatures != "" {
		r.Header.Set("X-Codex-Beta-Features", profile.BetaFeatures)
	}
	if profile.HasVersion {
		r.Header.Set("Version", profile.Version.String())
	}
}

func ResetCodexDeviceProfileCache() {
	codexDeviceProfileCacheMu.Lock()
	codexDeviceProfileCache = make(map[string]codexDeviceProfileCacheEntry)
	codexDeviceProfileCacheMu.Unlock()
}
