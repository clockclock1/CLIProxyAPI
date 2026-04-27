package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const (
	codexDeviceProfileTTL           = 7 * 24 * time.Hour
	codexDeviceProfileCleanupPeriod = time.Hour

	codexMinMinorVersion = 100
	codexMaxMinorVersion = 120
	codexMaxPatchVersion = 99
)

var (
	codexVersionPattern = regexp.MustCompile(`^codex(?:_cli_rs|_tui|_cli)/(\d+)\.(\d+)\.(\d+)`)

	codexDeviceProfileCache            = make(map[string]codexDeviceProfileCacheEntry)
	codexDeviceProfileCacheMu          sync.RWMutex
	codexDeviceProfileCacheCleanupOnce sync.Once
)

type codexOSProfile struct {
	Name    string
	Version string
	Arch    string
	Weight  float64
}

type codexTerminalProfile struct {
	Name   string
	Weight float64
}

type codexOriginatorProfile struct {
	Value  string
	Weight float64
}

var codexOSOptions = []codexOSProfile{
	{"Mac OS", "26.3.1", "arm64", 0.45},
	{"Mac OS", "15.2.0", "arm64", 0.15},
	{"Mac OS", "14.7.2", "x86_64", 0.10},
	{"Windows", "10.0", "x86_64", 0.12},
	{"Linux", "6.8.0", "x86_64", 0.10},
	{"Linux", "6.8.0", "aarch64", 0.08},
}

var codexTerminalOptions = []codexTerminalProfile{
	{"iTerm.app/3.6.9", 0.30},
	{"Terminal.app/460", 0.20},
	{"vscode/1.111.0", 0.25},
	{"WarpTerminal/0.2025.01.15", 0.10},
	{"WezTerm/20240101", 0.08},
	{"Alacritty/0.14.0", 0.07},
}

var codexOriginatorOptions = []codexOriginatorProfile{
	{"codex-tui", 0.55},
	{"codex-cli", 0.30},
	{"codex_cli_rs", 0.15},
}

type CodexDeviceProfile struct {
	UserAgent  string
	Originator string
	OS         string
	OSVersion  string
	Arch       string
	Terminal   string
	Version    string
	version    codexVersion
	hasVersion bool
}

type codexVersion struct {
	major int
	minor int
	patch int
}

type codexDeviceProfileCacheEntry struct {
	profile CodexDeviceProfile
	expire  time.Time
}

func codexDeviceProfileCacheKey(auth *cliproxyauth.Auth) string {
	var key string
	if auth != nil && strings.TrimSpace(auth.ID) != "" {
		key = "auth:" + strings.TrimSpace(auth.ID)
	} else {
		key = "global"
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func generateCodexDeviceProfile(auth *cliproxyauth.Auth, cfg *config.Config) CodexDeviceProfile {
	var seed int64
	if auth != nil && auth.ID != "" {
		h := sha256.Sum256([]byte(auth.ID))
		seed = int64(h[0])<<56 | int64(h[1])<<48 | int64(h[2])<<40 | int64(h[3])<<32 |
			int64(h[4])<<24 | int64(h[5])<<16 | int64(h[6])<<8 | int64(h[7])
	} else {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))

	osChoice := pickWeightedOS(rng)
	terminalChoice := pickWeightedTerminal(rng)
	originatorChoice := pickWeightedOriginator(rng)

	minorVersion := codexMinMinorVersion + rng.Intn(codexMaxMinorVersion-codexMinMinorVersion+1)
	patchVersion := rng.Intn(codexMaxPatchVersion + 1)
	version := fmt.Sprintf("%d.%d.%d", 0, minorVersion, patchVersion)

	var userAgent string
	switch originatorChoice {
	case "codex-tui":
		userAgent = fmt.Sprintf("codex-tui/%s (%s %s; %s) %s (codex-tui; %s)",
			version, osChoice.Name, osChoice.Version, osChoice.Arch, terminalChoice, version)
	case "codex-cli":
		userAgent = fmt.Sprintf("codex-cli/%s (%s %s; %s)",
			version, osChoice.Name, osChoice.Version, osChoice.Arch)
	case "codex_cli_rs":
		userAgent = fmt.Sprintf("codex_cli_rs/%s (%s %s; %s) %s",
			version, osChoice.Name, osChoice.Version, osChoice.Arch, terminalChoice)
	}

	profile := CodexDeviceProfile{
		UserAgent:  userAgent,
		Originator: originatorChoice,
		OS:         osChoice.Name,
		OSVersion:  osChoice.Version,
		Arch:       osChoice.Arch,
		Terminal:   terminalChoice,
		Version:    version,
	}

	if v, ok := parseCodexVersionFromUA(userAgent); ok {
		profile.version = v
		profile.hasVersion = true
	}

	return profile
}

func pickWeightedOS(rng *rand.Rand) codexOSProfile {
	total := 0.0
	for _, o := range codexOSOptions {
		total += o.Weight
	}
	r := rng.Float64() * total
	cumulative := 0.0
	for _, o := range codexOSOptions {
		cumulative += o.Weight
		if r <= cumulative {
			return o
		}
	}
	return codexOSOptions[0]
}

func pickWeightedTerminal(rng *rand.Rand) string {
	total := 0.0
	for _, t := range codexTerminalOptions {
		total += t.Weight
	}
	r := rng.Float64() * total
	cumulative := 0.0
	for _, t := range codexTerminalOptions {
		cumulative += t.Weight
		if r <= cumulative {
			return t.Name
		}
	}
	return codexTerminalOptions[0].Name
}

func pickWeightedOriginator(rng *rand.Rand) string {
	total := 0.0
	for _, o := range codexOriginatorOptions {
		total += o.Weight
	}
	r := rng.Float64() * total
	cumulative := 0.0
	for _, o := range codexOriginatorOptions {
		cumulative += o.Weight
		if r <= cumulative {
			return o.Value
		}
	}
	return codexOriginatorOptions[0].Value
}

func ResolveCodexDeviceProfile(auth *cliproxyauth.Auth, cfg *config.Config) CodexDeviceProfile {
	codexDeviceProfileCacheCleanupOnce.Do(startCodexDeviceProfileCacheCleanup)

	cacheKey := codexDeviceProfileCacheKey(auth)
	now := time.Now()

	codexDeviceProfileCacheMu.RLock()
	entry, hasCached := codexDeviceProfileCache[cacheKey]
	cachedValid := hasCached && entry.expire.After(now) && entry.profile.UserAgent != ""
	codexDeviceProfileCacheMu.RUnlock()

	if cachedValid {
		return entry.profile
	}

	profile := generateCodexDeviceProfile(auth, cfg)

	codexDeviceProfileCacheMu.Lock()
	codexDeviceProfileCache[cacheKey] = codexDeviceProfileCacheEntry{
		profile: profile,
		expire:  now.Add(codexDeviceProfileTTL),
	}
	codexDeviceProfileCacheMu.Unlock()

	return profile
}

func ApplyCodexDeviceProfileHeaders(r *http.Request, profile CodexDeviceProfile) {
	if r == nil {
		return
	}
	r.Header.Del("User-Agent")
	r.Header.Del("Originator")
	r.Header.Set("User-Agent", profile.UserAgent)
	r.Header.Set("Originator", profile.Originator)
}

func ResetCodexDeviceProfileCache() {
	codexDeviceProfileCacheMu.Lock()
	codexDeviceProfileCache = make(map[string]codexDeviceProfileCacheEntry)
	codexDeviceProfileCacheMu.Unlock()
}

func parseCodexVersionFromUA(userAgent string) (codexVersion, bool) {
	matches := codexVersionPattern.FindStringSubmatch(strings.TrimSpace(userAgent))
	if len(matches) != 4 {
		return codexVersion{}, false
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return codexVersion{}, false
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return codexVersion{}, false
	}
	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		return codexVersion{}, false
	}
	return codexVersion{major: major, minor: minor, patch: patch}, true
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

func MapCodexStainlessOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "MacOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	default:
		return "Other::" + runtime.GOOS
	}
}

func MapCodexStainlessArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		return "other::" + runtime.GOARCH
	}
}
