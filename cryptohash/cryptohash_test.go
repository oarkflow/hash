package cryptohash

import (
	"crypto/subtle"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// === BENCHMARKS ===

// BenchmarkCustomLightweight benchmarks our lightweight config
func BenchmarkCustomLightweight(b *testing.B) {
	password := []byte("test-password-12345")
	salt := []byte("random-salt-data")
	cfg := LightweightConfig()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = Hash(password, salt, cfg)
	}
}

// BenchmarkCustomFast benchmarks our fast config
func BenchmarkCustomFast(b *testing.B) {
	password := []byte("test-password-12345")
	salt := []byte("random-salt-data")
	cfg := FastConfig()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = Hash(password, salt, cfg)
	}
}

// BenchmarkCustomSecure benchmarks our secure config
func BenchmarkCustomSecure(b *testing.B) {
	password := []byte("test-password-12345")
	salt := []byte("random-salt-data")
	cfg := SecureConfig()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = Hash(password, salt, cfg)
	}
}

// BenchmarkArgon2id benchmarks standard Argon2id (comparable to our lightweight)
func BenchmarkArgon2id(b *testing.B) {
	password := []byte("test-password-12345")
	salt := []byte("random-salt-data")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(password, salt, 2, 4*1024, 4, 32)
	}
}

// BenchmarkArgon2idDefault benchmarks Argon2id with typical defaults
func BenchmarkArgon2idDefault(b *testing.B) {
	password := []byte("test-password-12345")
	salt := []byte("random-salt-data")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	}
}

// === PERFORMANCE COMPARISON TEST ===

func TestPerformanceComparison(t *testing.T) {
	password := []byte("test-password-12345")
	salt := []byte("random-salt-data")

	tests := []struct {
		name string
		fn   func()
	}{
		{
			"Custom-Fast (2MB, 1 iter)",
			func() { Hash(password, salt, FastConfig()) },
		},
		{
			"Custom-Lightweight (4MB, 1 iter)",
			func() { Hash(password, salt, LightweightConfig()) },
		},
		{
			"Custom-Secure (16MB, 1 iter)",
			func() { Hash(password, salt, SecureConfig()) },
		},
		{
			"Argon2id-Light (4MB, 2 iter)",
			func() { argon2.IDKey(password, salt, 2, 4*1024, 4, 32) },
		},
		{
			"Argon2id-Default (64MB, 3 iter)",
			func() { argon2.IDKey(password, salt, 3, 64*1024, 4, 32) },
		},
	}

	t.Log("\n=== Performance Comparison (10 iterations each) ===\n")

	for _, tt := range tests {
		start := time.Now()
		for i := 0; i < 10; i++ {
			tt.fn()
		}
		elapsed := time.Since(start)
		avg := elapsed / 10

		t.Logf("%-35s  Avg: %8s  Total: %8s", tt.name, avg, elapsed)
	}

	// Memory usage comparison
	t.Log("\n=== Memory Usage ===\n")
	t.Logf("Custom-Fast:       2 MB")
	t.Logf("Custom-Lightweight: 4 MB")
	t.Logf("Custom-Secure:     16 MB")
	t.Logf("Argon2id-Light:    4 MB")
	t.Logf("Argon2id-Default:  64 MB")
}

// TestCorrectness validates the implementation
func TestCorrectness(t *testing.T) {
	password := []byte("my-secret-password")
	salt := []byte("random-salt-1234")
	cfg := LightweightConfig()

	hash1 := Hash(password, salt, cfg)
	hash2 := Hash(password, salt, cfg)

	if subtle.ConstantTimeCompare(hash1, hash2) != 1 {
		t.Error("Same inputs should produce same hash")
	}

	if !Verify(password, salt, hash1, cfg) {
		t.Error("Verify should succeed with correct password")
	}

	wrongPass := []byte("wrong-password")
	if Verify(wrongPass, salt, hash1, cfg) {
		t.Error("Verify should fail with wrong password")
	}

	if len(hash1) != int(cfg.OutputLen) {
		t.Errorf("Hash length mismatch: got %d, want %d", len(hash1), cfg.OutputLen)
	}
}

func TestHashQuality(t *testing.T) {
	cfg := LightweightConfig() // Use more iterations for better diffusion

	// Test avalanche effect - small input change should cause large output change
	hash1 := Hash([]byte("password"), []byte("salt"), cfg)
	hash2 := Hash([]byte("password1"), []byte("salt"), cfg) // One character different

	// Count differing bits
	diffs := 0
	for i := 0; i < len(hash1) && i < len(hash2); i++ {
		for j := 0; j < 8; j++ {
			if (hash1[i]>>j)&1 != (hash2[i]>>j)&1 {
				diffs++
			}
		}
	}

	// Should have at least 40% bit differences for acceptable avalanche
	minDiffs := len(hash1) * 8 * 4 / 10
	if diffs < minDiffs {
		t.Errorf("Poor avalanche effect: only %d/%d bits differ (expected >= %d)", diffs, len(hash1)*8, minDiffs)
	}

	t.Logf("Avalanche test: %d/%d bits differ (%.1f%%)", diffs, len(hash1)*8, float64(diffs)/float64(len(hash1)*8)*100)
}

func TestCreateHashAndCompare(t *testing.T) {
	password := "test-password-123"

	// Create hash
	hash, err := CreateHash(password)
	if err != nil {
		t.Fatalf("CreateHash failed: %v", err)
	}

	// Verify format
	if !strings.Contains(hash, "$") {
		t.Error("Hash should contain separator")
	}

	// Compare with correct password
	if _, err := ComparePasswordAndHash(password, hash); err != nil {
		t.Errorf("ComparePasswordAndHash failed for correct password: %v", err)
	}

	// Compare with wrong password
	if _, err := ComparePasswordAndHash("wrong-password", hash); err == nil {
		t.Error("ComparePasswordAndHash should fail for wrong password")
	}

	// Test determinism - same password should give different hashes due to random salt
	hash2, err := CreateHash(password)
	if err != nil {
		t.Fatalf("CreateHash failed: %v", err)
	}
	if hash == hash2 {
		t.Error("Same password should produce different hashes due to random salt")
	}
}
