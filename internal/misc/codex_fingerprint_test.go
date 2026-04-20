package misc

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenerateCodexFingerprint_Deterministic(t *testing.T) {
	fp1 := GenerateCodexFingerprint("account-abc-123")
	fp2 := GenerateCodexFingerprint("account-abc-123")
	if fp1.UserAgent != fp2.UserAgent {
		t.Errorf("UA not deterministic: %q vs %q", fp1.UserAgent, fp2.UserAgent)
	}
	if fp1.MachineID != fp2.MachineID {
		t.Errorf("MachineID not deterministic: %q vs %q", fp1.MachineID, fp2.MachineID)
	}
	if fp1.ClientBuild != fp2.ClientBuild {
		t.Errorf("ClientBuild not deterministic: %q vs %q", fp1.ClientBuild, fp2.ClientBuild)
	}
}

func TestGenerateCodexFingerprint_Format(t *testing.T) {
	fp := GenerateCodexFingerprint("test-account")
	if !strings.HasPrefix(fp.UserAgent, "codex-tui/") {
		t.Errorf("UA should start with codex-tui/: %q", fp.UserAgent)
	}
	if !strings.Contains(fp.UserAgent, "Mac OS") {
		t.Errorf("UA should contain Mac OS: %q", fp.UserAgent)
	}
	if len(fp.MachineID) != 32 {
		t.Errorf("MachineID should be 32 hex chars, got %d: %q", len(fp.MachineID), fp.MachineID)
	}
	if len(fp.ClientBuild) != 12 {
		t.Errorf("ClientBuild should be 12 hex chars, got %d: %q", len(fp.ClientBuild), fp.ClientBuild)
	}
}

func TestGenerateCodexFingerprint_EmptyAccount(t *testing.T) {
	fp := GenerateCodexFingerprint("")
	if fp.UserAgent == "" {
		t.Error("empty account should still produce a UA")
	}
}

// TestGenerateCodexFingerprint_1000Accounts verifies that 1000 accounts produce
// very few UA collisions (birthday-problem expectation ≈ 0.3 collisions).
func TestGenerateCodexFingerprint_1000Accounts(t *testing.T) {
	const n = 1000
	uaSeen := make(map[string]string, n)
	machineIDSeen := make(map[string]string, n)
	uaCollisions := 0
	midCollisions := 0

	for i := 0; i < n; i++ {
		acc := fmt.Sprintf("openai-account-%06d", i)
		fp := GenerateCodexFingerprint(acc)

		if prev, ok := uaSeen[fp.UserAgent]; ok {
			uaCollisions++
			t.Logf("UA collision #%d: %q and %q share %q", uaCollisions, acc, prev, fp.UserAgent)
		} else {
			uaSeen[fp.UserAgent] = acc
		}

		if prev, ok := machineIDSeen[fp.MachineID]; ok {
			midCollisions++
			t.Logf("MachineID collision #%d: %q and %q share %q", midCollisions, acc, prev, fp.MachineID)
		} else {
			machineIDSeen[fp.MachineID] = acc
		}
	}

	// MachineID is a 16-byte hash — collisions should be essentially zero.
	if midCollisions > 0 {
		t.Errorf("MachineID had %d collisions across %d accounts (expected 0)", midCollisions, n)
	}

	// UA collision rate should be < 1% (i.e. < 10 collisions for 1000 accounts).
	collisionRate := float64(uaCollisions) / float64(n) * 100
	t.Logf("UA collisions: %d / %d (%.2f%%)", uaCollisions, n, collisionRate)
	if uaCollisions > 10 {
		t.Errorf("too many UA collisions: %d / %d (%.2f%%) — expand the fingerprint pool",
			uaCollisions, n, collisionRate)
	}
}

// TestGenerateCodexFingerprint_CombinationSpace documents the pool sizes.
func TestGenerateCodexFingerprint_CombinationSpace(t *testing.T) {
	total := len(codexTUIVersions) * len(macOSEntries) * len(archVariants) * len(terminalEntries)
	t.Logf("Combination space: %d versions × %d OS × %d arch × %d terminals = %d total",
		len(codexTUIVersions), len(macOSEntries), len(archVariants), len(terminalEntries), total)
	if total < 500_000 {
		t.Errorf("combination space too small: %d (want >= 500000)", total)
	}
}
