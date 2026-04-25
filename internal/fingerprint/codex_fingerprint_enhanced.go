package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// EnhancedCodexFingerprint extends CodexFingerprint with deeper real-user simulation fields.
// These fields mimic real codex-tui client behavior observed from actual traffic analysis.
type EnhancedCodexFingerprint struct {
	*CodexFingerprint

	// Timezone is the IANA timezone string (e.g., "America/New_York").
	// Real clients send this via system environment.
	Timezone string

	// ScreenResolution simulates the developer's monitor setup.
	// Format: "WIDTHxHEIGHT" (e.g., "2560x1440").
	ScreenResolution string

	// ColorDepth is the display color depth (24 or 32 typical for modern displays).
	ColorDepth int

	// TerminalColors is the number of colors supported by the terminal (256 or truecolor).
	TerminalColors string

	// Shell is the user's login shell (e.g., "/bin/zsh", "/bin/bash").
	Shell string

	// ShellVersion is the version of the shell.
	ShellVersion string

	// Locale is the system locale (e.g., "en_US.UTF-8").
	Locale string

	// GitVersion is the installed git version (developers typically have git).
	GitVersion string

	// NodeVersion is the installed Node.js version (many developers have this).
	NodeVersion string

	// PythonVersion is the installed Python version.
	PythonVersion string

	// GoVersion is the installed Go version (Go developers).
	GoVersion string

	// RustVersion is the installed Rust version.
	RustVersion string

	// VSCodeVersion simulates VS Code version if installed.
	VSCodeVersion string

	// CursorVersion simulates Cursor editor version if installed.
	CursorVersion string

	// HomebrewVersion is set if on Mac with Homebrew installed.
	HomebrewVersion string

	// DockerVersion is set if Docker is installed.
	DockerVersion string

	// SSHClient indicates if SSH client is available.
	SSHClient bool

	// TmuxSession indicates if running inside tmux.
	TmuxSession bool

	// TmuxVersion is the tmux version if applicable.
	TmuxVersion string

	// WorkingDirectory is a simulated typical project path.
	WorkingDirectory string

	// GitRepo indicates if current directory is a git repo.
	GitRepo bool

	// GitBranch is a simulated active git branch name.
	GitBranch string

	// LastLoginTime simulates realistic session timing.
	LastLoginTime time.Time

	// TypingSpeedWPM simulates the user's typing speed (affects request timing patterns).
	TypingSpeedWPM int

	// ThinkTimeMs is the simulated thinking time before requests.
	ThinkTimeMs int

	// EditorPreference indicates preferred editor (vscode, vim, nano, etc).
	EditorPreference string

	// PackageManager is the preferred package manager (npm, yarn, pnpm, pip, cargo, etc).
	PackageManager string

	// CIEnvironment is true if running in a CI-like environment (rare for real users, mostly false).
	CIEnvironment bool

	// DayOfWeekPreference simulates which days this user is most active.
	DayOfWeekPreference []time.Weekday

	// HourOfDayPreference simulates preferred active hours (0-23).
	HourOfDayPreference []int

	// RequestIntervalBase is the base interval between requests in ms.
	RequestIntervalBase int

	// JitterPercent is the random jitter percentage (0-50).
	JitterPercent int

	// SessionDurationAvg is average session duration in minutes.
	SessionDurationAvg int

	// ConcurrentProjects is number of projects this user typically works on.
	ConcurrentProjects int

	// CodeStylePreference indicates indentation style (tabs vs spaces).
	CodeStylePreference string

	// LineEndingPreference indicates CRLF vs LF preference.
	LineEndingPreference string

	// PreferredLanguages is a list of programming languages this user works with.
	PreferredLanguages []string

	// FrameworkPreference indicates preferred web framework if applicable.
	FrameworkPreference string

	// DatabasePreference indicates preferred database if applicable.
	DatabasePreference string

	// CloudProviderPreference indicates preferred cloud provider if applicable.
	CloudProviderPreference string

	// OSVersionDetail is detailed OS version string.
	OSVersionDetail string

	// KernelVersion is the kernel version string.
	KernelVersion string

	// UptimeDays is simulated system uptime in days.
	UptimeDays int

	// MemoryGB is simulated system memory.
	MemoryGB int

	// CPUCores is simulated CPU core count.
	CPUCores int

	// DiskType is SSD or HDD.
	DiskType string

	// GPUInfo is GPU information if applicable.
	GPUInfo string

	// NetworkType is the simulated network type (wifi, ethernet, 5g).
	NetworkType string

	// ISP is simulated Internet Service Provider.
	ISP string

	// Country is simulated user country.
	Country string

	// City is simulated user city.
	City string

	// Region is simulated user region/state.
	Region string

	// PostalCode is simulated postal code.
	PostalCode string

	// Latitude is simulated latitude.
	Latitude float64

	// Longitude is simulated longitude.
	Longitude float64
}

// enhancedCache stores computed enhanced fingerprints keyed by accountID.
var enhancedCache sync.Map

// timezonePool: realistic timezones for developers worldwide.
var timezonePool = []string{
	"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
	"America/Toronto", "America/Vancouver", "America/Mexico_City", "America/Sao_Paulo",
	"America/Buenos_Aires", "America/Bogota", "America/Lima",
	"Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Madrid",
	"Europe/Rome", "Europe/Amsterdam", "Europe/Zurich", "Europe/Stockholm",
	"Europe/Oslo", "Europe/Copenhagen", "Europe/Helsinki", "Europe/Vienna",
	"Europe/Prague", "Europe/Warsaw", "Europe/Budapest", "Europe/Bucharest",
	"Europe/Moscow", "Europe/Istanbul", "Europe/Kiev",
	"Asia/Tokyo", "Asia/Seoul", "Asia/Shanghai", "Asia/Hong_Kong",
	"Asia/Singapore", "Asia/Taipei", "Asia/Bangkok", "Asia/Jakarta",
	"Asia/Mumbai", "Asia/Dubai", "Asia/Tehran", "Asia/Karachi",
	"Asia/Manila", "Asia/Kuala_Lumpur", "Asia/Ho_Chi_Minh",
	"Australia/Sydney", "Australia/Melbourne", "Australia/Perth",
	"Pacific/Auckland", "Pacific/Fiji", "Africa/Cairo", "Africa/Johannesburg",
	"Africa/Lagos", "Africa/Nairobi",
}

// screenResolutions: common developer monitor resolutions.
var screenResolutions = []string{
	"2560x1440", "1920x1080", "3440x1440", "3840x2160",
	"1680x1050", "1440x900", "1280x800", "5120x2880",
	"3840x1600", "2560x1080", "1920x1200", "1366x768",
	"2880x1800", "3024x1964", "3456x2234",
}

// shells: common shells.
var shells = []string{
	"/bin/zsh", "/bin/bash", "/bin/fish", "/usr/bin/zsh",
	"/usr/bin/bash", "/opt/homebrew/bin/fish",
}

// shellVersions: version strings for shells.
var shellVersions = []string{
	"5.9", "5.8.1", "5.8", "3.2.57", "3.2.56",
	"5.2.15", "5.1.16", "5.0.17", "3.7.1", "3.6.1", "3.5.1",
}

// locales: common system locales.
var locales = []string{
	"en_US.UTF-8", "en_GB.UTF-8", "zh_CN.UTF-8", "zh_TW.UTF-8",
	"ja_JP.UTF-8", "ko_KR.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8",
	"es_ES.UTF-8", "pt_BR.UTF-8", "ru_RU.UTF-8", "it_IT.UTF-8",
	"pl_PL.UTF-8", "tr_TR.UTF-8", "nl_NL.UTF-8", "sv_SE.UTF-8",
	"en_CA.UTF-8", "en_AU.UTF-8", "en_IN.UTF-8",
}

// gitVersions: realistic git versions.
var gitVersions = []string{
	"2.49.0", "2.48.1", "2.47.2", "2.46.3", "2.45.3",
	"2.44.2", "2.43.5", "2.42.3", "2.41.1", "2.40.2",
}

// nodeVersions: realistic Node.js versions.
var nodeVersions = []string{
	"v22.14.0", "v22.13.1", "v22.12.0", "v22.11.0",
	"v20.18.3", "v20.18.2", "v20.18.1", "v20.17.0",
	"v20.16.0", "v20.15.1", "v20.14.0", "v20.13.1",
	"v18.20.6", "v18.20.5", "v18.20.4", "v18.19.1",
	"v23.6.0", "v23.5.0", "v23.4.0", "v23.3.0",
}

// pythonVersions: realistic Python versions.
var pythonVersions = []string{
	"3.13.2", "3.13.1", "3.13.0", "3.12.9", "3.12.8",
	"3.12.7", "3.12.6", "3.11.11", "3.11.10", "3.11.9",
	"3.10.16", "3.10.15", "3.10.14", "3.9.21", "3.9.20",
}

// goVersions: realistic Go versions.
var goVersions = []string{
	"go1.24.2", "go1.24.1", "go1.24.0", "go1.23.8",
	"go1.23.7", "go1.23.6", "go1.23.5", "go1.23.4",
	"go1.22.12", "go1.22.11", "go1.22.10", "go1.22.9",
}

// rustVersions: realistic Rust versions.
var rustVersions = []string{
	"1.85.0", "1.84.1", "1.84.0", "1.83.0", "1.82.0",
	"1.81.0", "1.80.1", "1.80.0", "1.79.0", "1.78.0",
}

// vscodeVersions: VS Code versions.
var vscodeVersions = []string{
	"1.99.2", "1.99.1", "1.99.0", "1.98.2", "1.98.1",
	"1.98.0", "1.97.2", "1.97.1", "1.97.0", "1.96.4",
}

// cursorVersions: Cursor editor versions.
var cursorVersions = []string{
	"0.48.9", "0.48.8", "0.48.7", "0.48.6", "0.48.5",
	"0.47.9", "0.47.8", "0.47.7", "0.47.6", "0.47.5",
	"", "", "", // Not everyone uses Cursor
}

// homebrewVersions: Homebrew versions (Mac only).
var homebrewVersions = []string{
	"4.4.31", "4.4.30", "4.4.29", "4.4.28", "4.4.27",
	"4.4.26", "4.4.25", "4.4.24", "4.4.23", "4.4.22",
}

// dockerVersions: Docker versions.
var dockerVersions = []string{
	"27.5.1", "27.5.0", "27.4.1", "27.4.0", "27.3.1",
	"27.3.0", "27.2.1", "27.2.0", "27.1.2", "27.1.1",
	"26.1.5", "26.1.4", "26.1.3", "26.1.2", "26.1.1",
	"", "", "", // Not everyone has Docker
}

// tmuxVersions: tmux versions.
var tmuxVersions = []string{
	"3.5a", "3.5", "3.4", "3.3a", "3.3", "3.2a", "3.2",
	"", "", "", // Many don't use tmux
}

// workingDirectories: realistic project paths.
var workingDirectories = []string{
	"~/projects/web-app", "~/dev/backend-api", "~/work/saas-platform",
	"~/code/mobile-app", "~/src/ai-project", "~/projects/ecommerce",
	"~/dev/microservices", "~/work/fintech-app", "~/code/game-engine",
	"~/projects/social-network", "~/dev/cli-tools", "~/work/data-pipeline",
	"~/src/ml-models", "~/projects/blockchain", "~/dev/serverless",
	"~/work/healthcare-app", "~/code/education-platform", "~/projects/realtime-chat",
}

// gitBranches: realistic branch names.
var gitBranches = []string{
	"main", "develop", "feature/user-auth", "feature/payment-integration",
	"bugfix/memory-leak", "refactor/api-v2", "hotfix/security-patch",
	"feature/ai-integration", "feature/dashboard-redesign", "bugfix/cors-issue",
	"feature/websocket-support", "refactor/database-layer", "feature/oauth2-login",
}

// editors: preferred editors.
var editors = []string{
	"vscode", "vim", "neovim", "cursor", "sublime", "intellij",
	"webstorm", "pycharm", "goland", "rustrover", "zed", "helix",
}

// packageManagers: preferred package managers.
var packageManagers = []string{
	"npm", "yarn", "pnpm", "pip", "poetry", "cargo", "go modules",
	"brew", "apt", "dnf", "pacman", "nix",
}

// preferredLanguages: programming languages.
var preferredLanguages = []string{
	"TypeScript", "JavaScript", "Python", "Go", "Rust", "Java",
	"C++", "C#", "Ruby", "PHP", "Swift", "Kotlin", "Scala",
	"Elixir", "Haskell", "Clojure", "Dart", "Lua",
}

// frameworks: web frameworks.
var frameworks = []string{
	"React", "Vue", "Angular", "Svelte", "Next.js", "Nuxt",
	"Express", "Fastify", "Django", "Flask", "FastAPI", "Spring Boot",
	"Rails", "Laravel", "Echo", "Gin", "Actix", "Axum",
	"", "", // Not everyone uses frameworks
}

// databases: database preferences.
var databases = []string{
	"PostgreSQL", "MySQL", "MongoDB", "Redis", "SQLite",
	"DynamoDB", "CockroachDB", "TiDB", "ClickHouse", "Elasticsearch",
	"Supabase", "Firebase", "PlanetScale", "Neon",
	"", "", // Not everyone specifies
}

// cloudProviders: cloud provider preferences.
var cloudProviders = []string{
	"AWS", "Google Cloud", "Azure", "DigitalOcean", "Linode",
	"Vercel", "Netlify", "Cloudflare", "Heroku", "Fly.io",
	"", "", // Not everyone uses cloud
}

// diskTypes: storage types.
var diskTypes = []string{"SSD", "NVMe SSD", "SSD", "SSD", "HDD"}

// gpuInfos: GPU information.
var gpuInfos = []string{
	"", "", "", "", // Most don't have dedicated GPU
	"Apple M3 Max", "Apple M3 Pro", "Apple M2 Max", "Apple M2 Pro", "Apple M1 Max",
	"NVIDIA RTX 4090", "NVIDIA RTX 4080", "NVIDIA RTX 4070", "NVIDIA RTX 3090",
	"NVIDIA RTX 3080", "NVIDIA A100", "NVIDIA H100",
}

// networkTypes: network connection types.
var networkTypes = []string{
	"WiFi 6", "WiFi 6E", "WiFi 7", "Ethernet 1Gbps", "Ethernet 2.5Gbps",
	"Ethernet 10Gbps", "5G", "4G LTE",
}

// isps: Internet Service Providers by region.
var isps = []string{
	"Comcast", "Verizon", "AT&T", "Spectrum", "T-Mobile",
	"BT", "Virgin Media", "Sky", "TalkTalk", "EE",
	"Orange", "Free", "SFR", "Deutsche Telekom", "Vodafone",
	"Telefonica", "TIM", "Swisscom", "Telia", "Elisa",
	"NTT", "SoftBank", "KDDI", "China Telecom", "China Unicom",
	"China Mobile", "Singtel", "StarHub", "Telstra", "Optus",
}

// countries: developer-heavy countries.
var countries = []string{
	"United States", "China", "India", "United Kingdom", "Germany",
	"France", "Canada", "Japan", "South Korea", "Australia",
	"Brazil", "Russia", "Netherlands", "Singapore", "Sweden",
	"Switzerland", "Poland", "Ukraine", "Israel", "Vietnam",
}

// citiesByCountry maps countries to realistic cities.
var citiesByCountry = map[string][]string{
	"United States":    {"San Francisco", "New York", "Seattle", "Austin", "Boston", "Los Angeles", "Chicago", "Denver", "Portland", "Miami"},
	"China":            {"Beijing", "Shanghai", "Shenzhen", "Hangzhou", "Guangzhou", "Chengdu", "Nanjing", "Wuhan", "Xi'an", "Suzhou"},
	"India":            {"Bangalore", "Mumbai", "Delhi", "Hyderabad", "Pune", "Chennai", "Kolkata", "Ahmedabad", "Jaipur", "Kochi"},
	"United Kingdom":   {"London", "Manchester", "Bristol", "Edinburgh", "Cambridge", "Oxford", "Leeds", "Glasgow", "Birmingham", "Liverpool"},
	"Germany":          {"Berlin", "Munich", "Hamburg", "Frankfurt", "Cologne", "Stuttgart", "Dresden", "Leipzig", "Dusseldorf", "Nuremberg"},
	"France":           {"Paris", "Lyon", "Marseille", "Toulouse", "Bordeaux", "Nantes", "Strasbourg", "Montpellier", "Lille", "Rennes"},
	"Canada":           {"Toronto", "Vancouver", "Montreal", "Calgary", "Ottawa", "Edmonton", "Quebec City", "Winnipeg", "Halifax", "Victoria"},
	"Japan":            {"Tokyo", "Osaka", "Kyoto", "Yokohama", "Fukuoka", "Sapporo", "Nagoya", "Kobe", "Sendai", "Hiroshima"},
	"South Korea":      {"Seoul", "Busan", "Incheon", "Daegu", "Daejeon", "Gwangju", "Suwon", "Ulsan", "Jeonju", "Chuncheon"},
	"Australia":        {"Sydney", "Melbourne", "Brisbane", "Perth", "Adelaide", "Canberra", "Gold Coast", "Newcastle", "Wollongong", "Hobart"},
	"Brazil":           {"Sao Paulo", "Rio de Janeiro", "Belo Horizonte", "Brasilia", "Curitiba", "Porto Alegre", "Recife", "Fortaleza", "Salvador", "Florianopolis"},
	"Russia":           {"Moscow", "Saint Petersburg", "Novosibirsk", "Yekaterinburg", "Kazan", "Nizhny Novgorod", "Samara", "Omsk", "Chelyabinsk", "Rostov-on-Don"},
	"Netherlands":      {"Amsterdam", "Rotterdam", "The Hague", "Utrecht", "Eindhoven", "Groningen", "Tilburg", "Breda", "Nijmegen", "Enschede"},
	"Singapore":        {"Singapore"},
	"Sweden":           {"Stockholm", "Gothenburg", "Malmö", "Uppsala", "Linköping", "Västerås", "Örebro", "Norrköping", "Helsingborg", "Jönköping"},
	"Switzerland":      {"Zurich", "Geneva", "Basel", "Bern", "Lausanne", "Lucerne", "St. Gallen", "Lugano", "Winterthur", "Neuchatel"},
	"Poland":           {"Warsaw", "Krakow", "Wroclaw", "Gdansk", "Poznan", "Lodz", "Katowice", "Lublin", "Bialystok", "Szczecin"},
	"Ukraine":          {"Kyiv", "Lviv", "Kharkiv", "Odesa", "Dnipro", "Vinnytsia", "Ivano-Frankivsk", "Chernivtsi", "Poltava", "Zhytomyr"},
	"Israel":           {"Tel Aviv", "Jerusalem", "Haifa", "Beersheba", "Netanya", "Rishon LeZion", "Petah Tikva", "Ashdod", "Holon", "Bnei Brak"},
	"Vietnam":          {"Ho Chi Minh City", "Hanoi", "Da Nang", "Hai Phong", "Can Tho", "Bien Hoa", "Hue", "Nha Trang", "Vung Tau", "Qui Nhon"},
}

// postalCodesByCountry maps countries to postal code patterns (prefixes).
var postalCodesByCountry = map[string][]string{
	"United States":    {"100", "941", "981", "787", "021", "902", "606", "802", "972", "331"},
	"China":            {"100", "200", "518", "310", "510", "610", "210", "430", "710", "215"},
	"India":            {"560", "400", "110", "500", "411", "600", "700", "380", "302", "682"},
	"United Kingdom":   {"SW1", "M1", "BS1", "EH1", "CB1", "OX1", "LS1", "G1", "B1", "L1"},
	"Germany":          {"101", "803", "200", "603", "506", "701", "010", "041", "402", "904"},
	"France":           {"750", "690", "130", "310", "330", "440", "670", "340", "590", "350"},
	"Canada":           {"M5V", "V6B", "H3A", "T2P", "K1P", "T5J", "G1R", "R3C", "B3J", "V8W"},
	"Japan":            {"100", "530", "600", "220", "810", "060", "450", "650", "980", "730"},
	"South Korea":      {"031", "471", "215", "414", "340", "619", "162", "446", "548", "242"},
	"Australia":        {"2000", "3000", "4000", "6000", "5000", "2600", "4217", "2300", "2500", "7000"},
	"Brazil":           {"010", "200", "301", "703", "800", "900", "500", "600", "400", "880"},
	"Russia":           {"101", "190", "630", "620", "420", "603", "443", "644", "454", "344"},
	"Netherlands":      {"101", "301", "251", "358", "561", "971", "503", "652", "681", "751"},
	"Singapore":        {"238", "539", "408", "238", "069", "238", "308", "529", "238", "609"},
	"Sweden":           {"111", "411", "211", "753", "581", "721", "702", "601", "252", "553"},
	"Switzerland":      {"800", "120", "405", "300", "100", "600", "900", "690", "840", "200"},
	"Poland":           {"00-", "30-", "50-", "80-", "60-", "90-", "40-", "20-", "70-", "10-"},
	"Ukraine":          {"010", "790", "610", "650", "490", "210", "760", "580", "360", "100"},
	"Israel":           {"610", "910", "310", "841", "420", "751", "490", "770", "581", "515"},
	"Vietnam":          {"700", "100", "550", "180", "900", "760", "530", "650", "780", "590"},
}

// regionsByCountry maps countries to regions/states.
var regionsByCountry = map[string][]string{
	"United States":    {"California", "New York", "Washington", "Texas", "Massachusetts", "Illinois", "Colorado", "Oregon", "Florida", "Pennsylvania"},
	"China":            {"Beijing", "Shanghai", "Guangdong", "Zhejiang", "Jiangsu", "Sichuan", "Hubei", "Shaanxi", "Shandong", "Henan"},
	"India":            {"Karnataka", "Maharashtra", "Delhi", "Telangana", "Tamil Nadu", "West Bengal", "Gujarat", "Rajasthan", "Kerala", "Haryana"},
	"United Kingdom":   {"England", "Scotland", "Wales", "Northern Ireland"},
	"Germany":          {"Bavaria", "Berlin", "Hamburg", "Hesse", "North Rhine-Westphalia", "Baden-Württemberg", "Saxony", "Brandenburg"},
	"France":           {"Île-de-France", "Auvergne-Rhône-Alpes", "Provence-Alpes-Côte d'Azur", "Occitanie", "Nouvelle-Aquitaine"},
	"Canada":           {"Ontario", "British Columbia", "Quebec", "Alberta", "Manitoba", "Nova Scotia", "Saskatchewan"},
	"Japan":            {"Tokyo", "Osaka", "Kanagawa", "Aichi", "Fukuoka", "Hokkaido", "Hyogo", "Kyoto"},
	"South Korea":      {"Seoul", "Busan", "Incheon", "Daegu", "Daejeon", "Gwangju", "Gyeonggi"},
	"Australia":        {"New South Wales", "Victoria", "Queensland", "Western Australia", "South Australia", "Tasmania", "ACT"},
	"Brazil":           {"São Paulo", "Rio de Janeiro", "Minas Gerais", "Federal District", "Paraná", "Rio Grande do Sul"},
	"Russia":           {"Moscow", "Saint Petersburg", "Novosibirsk Oblast", "Sverdlovsk Oblast", "Tatarstan"},
	"Netherlands":      {"North Holland", "South Holland", "Utrecht", "North Brabant", "Groningen"},
	"Singapore":        {"Central", "East", "North", "North-East", "West"},
	"Sweden":           {"Stockholm", "Västra Götaland", "Skåne", "Uppsala", "Östergötland"},
	"Switzerland":      {"Zurich", "Geneva", "Basel-City", "Bern", "Vaud"},
	"Poland":           {"Masovian", "Lesser Poland", "Silesian", "Greater Poland", "Lower Silesian"},
	"Ukraine":          {"Kyiv Oblast", "Lviv Oblast", "Kharkiv Oblast", "Odesa Oblast", "Dnipropetrovsk Oblast"},
	"Israel":           {"Tel Aviv District", "Jerusalem District", "Haifa District", "Southern District"},
	"Vietnam":          {"Ho Chi Minh City", "Hanoi", "Da Nang", "Hai Phong", "Can Tho"},
}

// ForAccountEnhanced returns the stable EnhancedCodexFingerprint for the given accountID.
// Uses sync.Map for lock-free concurrent access at 1000+ accounts scale.
func ForAccountEnhanced(accountID string) *EnhancedCodexFingerprint {
	if accountID == "" {
		return defaultEnhancedFingerprint()
	}
	if v, ok := enhancedCache.Load(accountID); ok {
		return v.(*EnhancedCodexFingerprint)
	}
	fp := computeEnhanced(accountID)
	actual, _ := enhancedCache.LoadOrStore(accountID, fp)
	return actual.(*EnhancedCodexFingerprint)
}

// computeEnhanced derives a deterministic, unique EnhancedCodexFingerprint from accountID.
func computeEnhanced(accountID string) *EnhancedCodexFingerprint {
	// Use a separate namespace from basic fingerprint to avoid collisions.
	h := sha256.Sum256([]byte("codex-fp-enhanced-v1:" + accountID))

	seed := binary.LittleEndian.Uint64(h[:8])
	sessionSeed := binary.LittleEndian.Uint64(h[8:16])
	reqIDSeed := binary.LittleEndian.Uint64(h[16:24])
	geoSeed := binary.LittleEndian.Uint64(h[24:32])

	r := rand.New(rand.NewSource(int64(seed))) //nolint:gosec
	geoR := rand.New(rand.NewSource(int64(geoSeed))) //nolint:gosec

	// Get base fingerprint.
	baseFP := computeWithSeeds(accountID, seed, sessionSeed, reqIDSeed)

	// Geographic simulation.
	country := pick(geoR, countries)
	cities := citiesByCountry[country]
	city := pick(geoR, cities)
	regions := regionsByCountry[country]
	region := pick(geoR, regions)
	postalPrefixes := postalCodesByCountry[country]
	postalPrefix := pick(geoR, postalPrefixes)
	postalSuffix := geoR.Intn(900) + 100
	postalCode := fmt.Sprintf("%s%d", postalPrefix, postalSuffix)

	// Latitude/longitude roughly around the city (simplified).
	lat := (geoR.Float64() * 140) - 70 // -70 to +70
	lng := (geoR.Float64() * 360) - 180

	// ISP based on country.
	isp := pick(geoR, isps)

	// System specs.
	memGB := []int{8, 16, 16, 32, 32, 32, 64, 64, 128, 128, 256}
	cpuCores := []int{4, 4, 6, 8, 8, 8, 12, 16, 16, 24, 32, 64}

	// Determine if Mac (from base fingerprint).
	isMac := strings.Contains(baseFP.UserAgent, "Mac OS")

	// Software versions.
	var homebrew, docker string
	if isMac {
		homebrew = pick(r, homebrewVersions)
	}
	docker = pick(r, dockerVersions)

	// tmux usage (~30% of developers).
	tmux := ""
	inTmux := false
	if r.Intn(100) < 30 {
		tmux = pick(r, tmuxVersions)
		inTmux = true
	}

	// SSH client (~80% have it).
	sshClient := r.Intn(100) < 80

	// Git repo simulation (~70% are in a git repo).
	inGitRepo := r.Intn(100) < 70
	branch := ""
	if inGitRepo {
		branch = pick(r, gitBranches)
	}

	// Typing speed (40-120 WPM).
	typingSpeed := 40 + r.Intn(80)

	// Think time (100-3000ms).
	thinkTime := 100 + r.Intn(2900)

	// Request interval base (500-5000ms).
	reqInterval := 500 + r.Intn(4500)

	// Jitter percent (5-30%).
	jitter := 5 + r.Intn(25)

	// Session duration average (10-240 minutes).
	sessionDuration := 10 + r.Intn(230)

	// Concurrent projects (1-8).
	concurrentProjects := 1 + r.Intn(7)

	// Preferred languages (1-4).
	numLangs := 1 + r.Intn(4)
	langs := make([]string, 0, numLangs)
	seenLangs := make(map[string]struct{})
	for i := 0; i < numLangs && i < 10; i++ {
		lang := pick(r, preferredLanguages)
		if _, ok := seenLangs[lang]; !ok {
			seenLangs[lang] = struct{}{}
			langs = append(langs, lang)
		}
	}

	// Active days (2-5 days per week).
	numDays := 2 + r.Intn(4)
	activeDays := make([]time.Weekday, 0, numDays)
	seenDays := make(map[time.Weekday]struct{})
	for i := 0; i < numDays && i < 7; i++ {
		d := time.Weekday(r.Intn(7))
		if _, ok := seenDays[d]; !ok {
			seenDays[d] = struct{}{}
			activeDays = append(activeDays, d)
		}
	}

	// Active hours (4-12 hours per day).
	numHours := 4 + r.Intn(9)
	activeHours := make([]int, 0, numHours)
	seenHours := make(map[int]struct{})
	for i := 0; i < numHours && i < 16; i++ {
		hour := r.Intn(24)
		if _, ok := seenHours[hour]; !ok {
			seenHours[hour] = struct{}{}
			activeHours = append(activeHours, hour)
		}
	}

	return &EnhancedCodexFingerprint{
		CodexFingerprint: baseFP,
		Timezone:         pick(r, timezonePool),
		ScreenResolution: pick(r, screenResolutions),
		ColorDepth:       []int{24, 32, 32, 32, 30}[r.Intn(5)],
		TerminalColors:   []string{"256", "truecolor", "truecolor", "truecolor"}[r.Intn(4)],
		Shell:            pick(r, shells),
		ShellVersion:     pick(r, shellVersions),
		Locale:           pick(r, locales),
		GitVersion:       pick(r, gitVersions),
		NodeVersion:      pick(r, nodeVersions),
		PythonVersion:    pick(r, pythonVersions),
		GoVersion:        pick(r, goVersions),
		RustVersion:      pick(r, rustVersions),
		VSCodeVersion:    pick(r, vscodeVersions),
		CursorVersion:    pick(r, cursorVersions),
		HomebrewVersion:  homebrew,
		DockerVersion:    docker,
		SSHClient:        sshClient,
		TmuxSession:      inTmux,
		TmuxVersion:      tmux,
		WorkingDirectory: pick(r, workingDirectories),
		GitRepo:          inGitRepo,
		GitBranch:        branch,
		LastLoginTime:    time.Now().Add(-time.Duration(r.Intn(168)) * time.Hour),
		TypingSpeedWPM:   typingSpeed,
		ThinkTimeMs:      thinkTime,
		EditorPreference: pick(r, editors),
		PackageManager:   pick(r, packageManagers),
		CIEnvironment:    false, // Real users are rarely in CI
		DayOfWeekPreference: activeDays,
		HourOfDayPreference: activeHours,
		RequestIntervalBase: reqInterval,
		JitterPercent:       jitter,
		SessionDurationAvg:  sessionDuration,
		ConcurrentProjects:  concurrentProjects,
		CodeStylePreference: []string{"spaces", "spaces", "spaces", "tabs"}[r.Intn(4)],
		LineEndingPreference: []string{"LF", "LF", "LF", "CRLF"}[r.Intn(4)],
		PreferredLanguages:  langs,
		FrameworkPreference: pick(r, frameworks),
		DatabasePreference:  pick(r, databases),
		CloudProviderPreference: pick(r, cloudProviders),
		OSVersionDetail:     baseFP.Platform,
		KernelVersion:       baseFP.Platform,
		UptimeDays:          r.Intn(30),
		MemoryGB:            memGB[r.Intn(len(memGB))],
		CPUCores:            cpuCores[r.Intn(len(cpuCores))],
		DiskType:            pick(r, diskTypes),
		GPUInfo:             pick(r, gpuInfos),
		NetworkType:         pick(r, networkTypes),
		ISP:                 isp,
		Country:             country,
		City:                city,
		Region:              region,
		PostalCode:          postalCode,
		Latitude:            lat,
		Longitude:           lng,
	}
}

// computeWithSeeds allows computing base fingerprint with pre-derived seeds.
func computeWithSeeds(accountID string, seed, sessionSeed, reqIDSeed uint64) *CodexFingerprint {
	h := sha256.Sum256([]byte("codex-fp-v2:" + accountID))
	_ = h

	r := rand.New(rand.NewSource(int64(seed))) //nolint:gosec

	isMac := (seed % 100) < 72
	codexVer := pick(r, codexVersions)

	var ua, platform, arch string
	if isMac {
		macVer := pick(r, macOSMarketingVersions)
		macArch := pick(r, macArches)
		term := pick(r, terminalApps)
		platform = "Mac OS " + macVer
		arch = macArch
		ua = fmt.Sprintf("codex-tui/%s (%s; %s) %s (codex-tui; %s)",
			codexVer, platform, arch, term, codexVer)
	} else {
		kernel := pick(r, linuxKernels)
		linuxArch := pick(r, linuxArches)
		platform = "Linux " + kernel
		arch = linuxArch
		ua = fmt.Sprintf("codex-tui/%s (%s; %s) (codex-tui; %s)",
			codexVer, platform, arch, codexVer)
	}

	betaFeatures := pick(r, betaFeatureSets)
	acceptLang := pick(r, acceptLanguages)

	dntVal := ""
	dntRoll := r.Intn(10)
	if dntRoll < 6 {
		dntVal = "0"
	} else if dntRoll < 9 {
		dntVal = "1"
	}

	turnMeta := generateTurnMetadata(r, codexVer, platform, arch)
	clientReqPrefix := newUUID(reqIDSeed)

	return &CodexFingerprint{
		UserAgent:             ua,
		SessionSeed:           sessionSeed,
		Version:               codexVer,
		BetaFeatures:          betaFeatures,
		Platform:              platform,
		Arch:                  arch,
		TurnMetadata:          turnMeta,
		ClientRequestIDPrefix: clientReqPrefix,
		AcceptLanguage:        acceptLang,
		DNT:                   dntVal,
		SecFetchSite:          "",
		SecFetchMode:          "",
		SecFetchDest:          "",
	}
}

// defaultEnhancedFingerprint returns a generic enhanced fingerprint.
func defaultEnhancedFingerprint() *EnhancedCodexFingerprint {
	return &EnhancedCodexFingerprint{
		CodexFingerprint:     defaultFingerprint(),
		Timezone:             "America/New_York",
		ScreenResolution:     "2560x1440",
		ColorDepth:           32,
		TerminalColors:       "truecolor",
		Shell:                "/bin/zsh",
		ShellVersion:         "5.9",
		Locale:               "en_US.UTF-8",
		GitVersion:           "2.49.0",
		NodeVersion:          "v22.14.0",
		PythonVersion:        "3.13.2",
		GoVersion:            "go1.24.2",
		RustVersion:          "1.85.0",
		VSCodeVersion:        "1.99.2",
		CursorVersion:        "",
		HomebrewVersion:      "4.4.31",
		DockerVersion:        "27.5.1",
		SSHClient:            true,
		TmuxSession:          false,
		TmuxVersion:          "",
		WorkingDirectory:     "~/projects/web-app",
		GitRepo:              true,
		GitBranch:            "main",
		LastLoginTime:        time.Now().Add(-24 * time.Hour),
		TypingSpeedWPM:       65,
		ThinkTimeMs:          500,
		EditorPreference:     "vscode",
		PackageManager:       "npm",
		CIEnvironment:        false,
		DayOfWeekPreference:  []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
		HourOfDayPreference:  []int{9, 10, 11, 14, 15, 16, 17},
		RequestIntervalBase:  2000,
		JitterPercent:        15,
		SessionDurationAvg:   120,
		ConcurrentProjects:   3,
		CodeStylePreference:  "spaces",
		LineEndingPreference: "LF",
		PreferredLanguages:   []string{"TypeScript", "Python"},
		FrameworkPreference:  "React",
		DatabasePreference:   "PostgreSQL",
		CloudProviderPreference: "AWS",
		OSVersionDetail:      "Mac OS 15.4.1",
		KernelVersion:        "Mac OS 15.4.1",
		UptimeDays:           5,
		MemoryGB:             32,
		CPUCores:             8,
		DiskType:             "SSD",
		GPUInfo:              "",
		NetworkType:          "WiFi 6",
		ISP:                  "Comcast",
		Country:              "United States",
		City:                 "San Francisco",
		Region:               "California",
		PostalCode:           "94105",
		Latitude:             37.7749,
		Longitude:            -122.4194,
	}
}

// WarmEnhancedCache pre-computes enhanced fingerprints for a list of account IDs.
func WarmEnhancedCache(accountIDs []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for _, id := range accountIDs {
		if id == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(aid string) {
			defer wg.Done()
			defer func() { <-sem }()
			ForAccountEnhanced(aid)
		}(id)
	}
	wg.Wait()
}

// EnhancedCacheStats returns the number of enhanced fingerprints currently cached.
func EnhancedCacheStats() int {
	count := 0
	enhancedCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// ShouldMakeRequest determines if this account should make a request now based on
// their simulated usage patterns (active days/hours).
func (fp *EnhancedCodexFingerprint) ShouldMakeRequest() bool {
	if fp == nil {
		return true
	}
	now := time.Now()

	// Check day of week preference.
	if len(fp.DayOfWeekPreference) > 0 {
		found := false
		for _, d := range fp.DayOfWeekPreference {
			if d == now.Weekday() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check hour of day preference.
	if len(fp.HourOfDayPreference) > 0 {
		found := false
		for _, h := range fp.HourOfDayPreference {
			if h == now.Hour() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// NextRequestDelay returns a realistic delay before the next request,
// incorporating the account's typing speed, think time, and jitter.
func (fp *EnhancedCodexFingerprint) NextRequestDelay() time.Duration {
	if fp == nil {
		return RequestDelay(nil)
	}

	// Base delay from typing speed and think time.
	baseDelay := time.Duration(fp.ThinkTimeMs) * time.Millisecond

	// Add typing-speed-derived delay (faster typers = shorter delays).
	typingDelay := time.Duration(60000/fp.TypingSpeedWPM) * time.Millisecond

	// Add jitter.
	jitter := (fp.SessionSeed ^ uint64(nanoTime())) % uint64(fp.JitterPercent*10)
	jitterDelay := time.Duration(jitter) * time.Millisecond

	total := baseDelay + typingDelay + jitterDelay
	if total < 100*time.Millisecond {
		total = 100 * time.Millisecond
	}
	return total
}

// SessionDuration returns a realistic session duration for this account.
func (fp *EnhancedCodexFingerprint) SessionDuration() time.Duration {
	if fp == nil {
		return 30 * time.Minute
	}
	// Add some variance around the average.
	variance := (fp.SessionSeed % 40) - 20 // +/- 20%
	duration := time.Duration(fp.SessionDurationAvg) * time.Minute
	duration = time.Duration(int64(duration) * int64(100+variance) / 100)
	if duration < 5*time.Minute {
		duration = 5 * time.Minute
	}
	return duration
}

// UserAgentString returns the full User-Agent string.
func (fp *EnhancedCodexFingerprint) UserAgentString() string {
	if fp == nil || fp.CodexFingerprint == nil {
		return "codex-tui/0.118.0 (Mac OS 15.4.1; arm64) iTerm.app/3.5.10 (codex-tui; 0.118.0)"
	}
	return fp.UserAgent
}

// IsActiveHours returns true if current time is within this user's typical active hours.
func (fp *EnhancedCodexFingerprint) IsActiveHours() bool {
	if fp == nil || len(fp.HourOfDayPreference) == 0 {
		return true
	}
	currentHour := time.Now().Hour()
	for _, h := range fp.HourOfDayPreference {
		if h == currentHour {
			return true
		}
	}
	return false
}

// IsActiveDay returns true if today is one of this user's typical active days.
func (fp *EnhancedCodexFingerprint) IsActiveDay() bool {
	if fp == nil || len(fp.DayOfWeekPreference) == 0 {
		return true
	}
	today := time.Now().Weekday()
	for _, d := range fp.DayOfWeekPreference {
		if d == today {
			return true
		}
	}
	return false
}


