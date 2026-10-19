package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// TestTOTPMatchesRFC6238Vectors pins the implementation to the algorithm's own
// published test vectors.
//
// This is the test that matters for TOTP: an off-by-one in the truncation
// offset or the counter encoding still yields plausible-looking 6-digit codes,
// so only the RFC's known-answer values prove interoperability with Google
// Authenticator. RFC 6238 Appendix B uses a 20-byte ASCII secret for SHA-1.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// "12345678901234567890" is the RFC's SHA-1 seed, base32-encoded.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},          // 1970-01-01 00:00:59 UTC
		{1111111109, "07081804"},  // 2005-03-18 01:58:29 UTC
		{1111111111, "14050471"},  // 2005-03-18 01:58:31 UTC
		{1234567890, "89005924"},  // 2009-02-13 23:31:30 UTC
		{2000000000, "69279037"},  // 2033-05-18 03:33:20 UTC
		{20000000000, "65353130"}, // 2603-10-11 11:33:20 UTC
	}
	for _, c := range cases {
		got, err := GenerateTOTP(secret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("t=%d: %v", c.unix, err)
		}
		// The RFC prints 8 digits; ours is 6 by configuration, so compare the
		// low 6 digits (the truncation is the same, only the modulo differs).
		if want := c.want[len(c.want)-6:]; got != want {
			t.Errorf("GenerateTOTP(t=%d) = %s, want %s (RFC 6238 vector)", c.unix, got, want)
		}
	}
}

func TestGenerateTOTPSecretIsBase32AndUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 40; i++ {
		s, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if strings.Contains(s, "=") {
			t.Fatalf("secret %q is padded; authenticator apps reject '='", s)
		}
		if _, err := decodeTOTPSecret(s); err != nil {
			t.Fatalf("secret %q does not decode: %v", s, err)
		}
		if seen[s] {
			t.Fatalf("duplicate secret generated: %q", s)
		}
		seen[s] = true
	}
}

func TestVerifyTOTPAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := GenerateTOTP(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code, now) {
		t.Fatalf("code %s rejected at the time it was generated for", code)
	}
}

// Clock drift is the normal case, not the exception: a phone's clock and the
// server's are never perfectly aligned, so one step either side must be
// accepted or 2FA becomes an intermittent lockout.
func TestVerifyTOTPToleratesOneStepSkew(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0).UTC()

	for _, offset := range []time.Duration{-20 * time.Second, 0, 20 * time.Second} {
		code, err := GenerateTOTP(secret, now.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyTOTP(secret, code, now) {
			t.Errorf("code generated %s away was rejected (within the accepted skew)", offset)
		}
	}
}

// The skew window must stay narrow: accepting too many steps would widen the
// brute-force space for a 6-digit code.
func TestVerifyTOTPRejectsBeyondSkewWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0).UTC()

	for _, offset := range []time.Duration{-90 * time.Second, 90 * time.Second, -5 * time.Minute, 24 * time.Hour} {
		code, err := GenerateTOTP(secret, now.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		if VerifyTOTP(secret, code, now) {
			t.Errorf("code generated %s away was accepted; skew window is too wide", offset)
		}
	}
}

func TestVerifyTOTPRejectsMalformedInput(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0).UTC()

	for _, code := range []string{
		"", " ", "12345", "1234567", // wrong length
		"abcdef", "12 456", "12345a", // not all digits
		"000000", // valid shape, astronomically unlikely to be the real code
	} {
		if VerifyTOTP(secret, code, now) {
			t.Errorf("code %q was accepted", code)
		}
	}
	// A malformed secret must never authenticate.
	valid, _ := GenerateTOTP(secret, now)
	if VerifyTOTP("not!base32", valid, now) {
		t.Error("a code was accepted against an undecodable secret")
	}
	if VerifyTOTP("", valid, now) {
		t.Error("a code was accepted against an empty secret")
	}
}

func TestTOTPUriIsScannable(t *testing.T) {
	uri := TOTPUri("pk@statetrack.io", "GEZDGNBVGY3TQOJQ")
	for _, want := range []string{
		"otpauth://totp/",
		"StateTrack",
		"secret=GEZDGNBVGY3TQOJQ",
		"issuer=StateTrack",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q is missing %q", uri, want)
		}
	}
}

/* -------------------------------------------------------------------------- */
/* Tokens                                                                     */
/* -------------------------------------------------------------------------- */

func TestGenerateTokenShapeAndEntropy(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		token, prefix, err := GenerateToken(APIKeyPrefix)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(token, "st_live_") {
			t.Fatalf("token %q lacks the st_live_ prefix", token)
		}
		if want := "st_live_" + token[len("st_live_"):len("st_live_")+prefixDisplayChars]; prefix != want {
			t.Fatalf("prefix = %q, want %q", prefix, want)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated: %q", token)
		}
		seen[token] = true
	}
}

func TestHashTokenIsSHA256AndStable(t *testing.T) {
	token, _, _ := GenerateToken(APIKeyPrefix)

	// Known-answer check so a refactor cannot silently change the digest and
	// invalidate every stored key. sha256("st_live_abc") is computed here with
	// the standard library rather than hardcoded, so the assertion is about the
	// encoding (hex, lowercase, no salt, no truncation) rather than restating
	// the implementation's own arithmetic.
	sum := sha256.Sum256([]byte("st_live_abc"))
	if want, got := hex.EncodeToString(sum[:]), HashToken("st_live_abc"); got != want {
		t.Fatalf("HashToken = %q, want %q (plain lowercase SHA-256 hex)", got, want)
	}
	if got := HashToken(token); len(got) != 64 {
		t.Fatalf("HashToken returned %d hex chars, want 64", len(got))
	}
	if strings.ToLower(HashToken(token)) != HashToken(token) {
		t.Error("HashToken is not lowercase hex")
	}

	if HashToken(token) != HashToken(token) {
		t.Error("HashToken is not deterministic")
	}
	if HashToken(token) == HashToken(token+"x") {
		t.Error("distinct tokens produced the same hash")
	}
	// Surrounding whitespace is a paste artifact, not part of the secret.
	if HashToken(token) != HashToken("  "+token+"\n") {
		t.Error("HashToken does not trim whitespace")
	}
}

func TestTokenPrefixOf(t *testing.T) {
	token, prefix, _ := GenerateToken(EnrollmentPrefix)
	if got := TokenPrefixOf(token, EnrollmentPrefix); got != prefix {
		t.Errorf("TokenPrefixOf = %q, want %q", got, prefix)
	}
	// A mismatched or truncated kind must yield no prefix rather than garbage.
	if got := TokenPrefixOf(token, APIKeyPrefix); got != "" {
		t.Errorf("TokenPrefixOf with wrong kind = %q, want empty", got)
	}
	if got := TokenPrefixOf("st_live_", APIKeyPrefix); got != "" {
		t.Errorf("TokenPrefixOf on a too-short token = %q, want empty", got)
	}
}

/* -------------------------------------------------------------------------- */
/* Passwords                                                                  */
/* -------------------------------------------------------------------------- */

func TestPasswordHashRoundTrip(t *testing.T) {
	const pw = "correct horse battery staple"
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, pw) {
		t.Fatal("the encoded hash contains the plaintext password")
	}
	if !VerifyPassword(hash, pw) {
		t.Error("the correct password was rejected")
	}
	// A single-character difference must fail; this is the whole point.
	for _, wrong := range []string{"", "Correct horse battery staple", pw + " ", pw[:len(pw)-1]} {
		if VerifyPassword(hash, wrong) {
			t.Errorf("password %q was accepted", wrong)
		}
	}
}

func TestPasswordHashIsSaltedUniquely(t *testing.T) {
	a, _ := HashPassword("same-password")
	b, _ := HashPassword("same-password")
	if a == b {
		t.Fatal("hashing the same password twice produced an identical hash (no unique salt)")
	}
}

func TestPasswordHashCarriesItsParameters(t *testing.T) {
	hash, _ := HashPassword("pw")
	parts := strings.Split(hash, "$")
	if len(parts) != 4 {
		t.Fatalf("encoded hash %q is not in the documented 4-part format", hash)
	}
	if parts[0] != "pbkdf2_sha256" {
		t.Errorf("algorithm tag = %q, want pbkdf2_sha256", parts[0])
	}
	// Verification reads the iteration count from the hash, which is what makes
	// raising the work factor non-breaking. Prove it by verifying a hash
	// re-encoded with a different (lower) count.
	low := strings.Join([]string{parts[0], "1000", parts[2], parts[3]}, "$")
	if VerifyPassword(low, "pw") {
		t.Error("a hash with a tampered iteration count still verified")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	for _, hash := range []string{
		"", "$$$", "pbkdf2_sha256$$", "pbkdf2_sha256$abc$x$y",
		"pbkdf2_sha256$1000$nothex$nothex", "bcrypt$1000$aa$bb",
		"pbkdf2_sha256$1000$00$",
	} {
		if VerifyPassword(hash, "anything") {
			t.Errorf("malformed hash %q verified", hash)
		}
	}
}
