// Package security holds the cryptographic primitives the server uses for
// identity: TOTP (RFC 6238) second factors, password hashing, and the generation
// and hashing of API keys and enrollment tokens.
//
// It deliberately has no dependencies beyond the standard library. These
// functions decide whether a request is authenticated and whether a secret can
// be replayed, so they are the last place that should pull in a transitive
// supply chain — and a stdlib-only implementation can be unit tested without
// standing up a database or an HTTP server.
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters. These are the values every authenticator app (Google
// Authenticator, 1Password, Authy) assumes by default, so they are written into
// the otpauth URI explicitly rather than being left to the app's defaults.
const (
	// TOTPPeriod is the code lifetime in seconds.
	TOTPPeriod = 30
	// TOTPDigits is the code length.
	TOTPDigits = 6
	// TOTPSecretBytes is the raw secret size before base32 encoding. RFC 4226
	// requires at least 128 bits and recommends 160 for SHA-1, which is one
	// hash block — the size that makes the HMAC key contribute maximally.
	TOTPSecretBytes = 20
	// TOTPSkewSteps is how many steps either side of "now" are accepted, to
	// tolerate clock drift between the server and the phone. One step is ±30s,
	// which covers real-world NTP drift without widening the brute-force window
	// enough to matter for a 6-digit code.
	TOTPSkewSteps = 1
	// TOTPIssuer is the label shown in the authenticator app.
	TOTPIssuer = "StateTrack"
)

// base32NoPad is the alphabet authenticator apps use. Padding '=' is stripped:
// Google Authenticator rejects a padded secret.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh base32-encoded secret, ready for an
// otpauth URI.
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32NoPad.EncodeToString(buf), nil
}

// hotp computes the RFC 4226 HOTP value for a counter.
//
// The algorithm: HMAC-SHA1 the 8-byte big-endian counter, then "dynamic
// truncation" — use the low nibble of the last byte as an offset into the
// digest and read 4 bytes from there, which is what makes the output uniform
// rather than biased by the digest's distribution.
func hotp(secret []byte, counter uint64) (string, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secret)
	if _, err := mac.Write(buf[:]); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	// Left-pad to the configured width; the modulo bounds it, so this is a
	// zero-padded decimal, not a truncation of a longer number.
	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, code%mod), nil
}

// GenerateTOTP returns the 6-digit code for a secret at a point in time.
func GenerateTOTP(secret string, at time.Time) (string, error) {
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(raw, uint64(at.Unix()/TOTPPeriod))
}

// VerifyTOTP reports whether a code is valid for the secret right now,
// accepting TOTPSkewSteps either side of the current step.
//
// Comparison is constant-time and every candidate is evaluated even after a
// match, so the response time does not reveal which step matched.
func VerifyTOTP(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	// Reject anything that is not exactly the expected digit count before doing
	// crypto work: a 3-digit guess can never be valid, and this keeps the
	// comparison below a fixed-length operation.
	if len(code) != TOTPDigits {
		return false
	}
	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}

	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return false
	}

	counter := uint64(at.Unix() / TOTPPeriod)
	matched := false
	for step := -TOTPSkewSteps; step <= TOTPSkewSteps; step++ {
		// Guard the unsigned arithmetic: at the Unix epoch a negative skew would
		// wrap to a colossal counter and generate a code for the year 5 billion.
		if step < 0 && counter < uint64(-step) {
			continue
		}
		candidate, err := hotp(raw, counter+uint64(step))
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			matched = true
		}
	}
	return matched
}

// decodeTOTPSecret accepts a base32 secret with or without padding and in any
// case, because operators paste secrets from IdPs and authenticator apps that
// disagree on all three.
func decodeTOTPSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("empty totp secret")
	}
	raw, err := base32NoPad.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode totp secret: %w", err)
	}
	return raw, nil
}

// TOTPUri builds the standard otpauth:// URI an authenticator app consumes,
// either as a QR code or a manual entry key.
//
//	otpauth://totp/StateTrack:user@example.com?secret=...&issuer=StateTrack&...
func TOTPUri(account, secret string) string {
	label := TOTPIssuer + ":" + strings.TrimSpace(account)
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", TOTPIssuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	params.Set("period", fmt.Sprintf("%d", TOTPPeriod))
	return "otpauth://totp/" + url.PathEscape(label) + "?" + params.Encode()
}

/* -------------------------------------------------------------------------- */
/* Token generation and hashing                                               */
/* -------------------------------------------------------------------------- */

// Token kinds. The prefix makes a leaked credential immediately identifiable in
// a log or a screenshot, and lets a secret scanner recognise it.
const (
	// APIKeyPrefix is the prefix for console/API credentials.
	APIKeyPrefix = "st_live_"
	// EnrollmentPrefix is the prefix for agent bootstrap tokens.
	EnrollmentPrefix = "st_enroll_"
	// tokenRandomBytes is the entropy behind a generated secret. 24 bytes is
	// 192 bits, which puts brute force far out of reach for a value that can
	// never be rotated faster than an operator reacts.
	tokenRandomBytes = 24
	// prefixDisplayChars is how many characters of the random part are kept in
	// cleartext as a display identifier, e.g. "st_live_8f9a".
	prefixDisplayChars = 4
)

// GenerateToken returns a fresh secret and the display prefix that may be stored
// alongside its hash.
//
// The prefix is derived from the random part, not a constant, so two keys minted
// in the same second are still distinguishable in a list.
func GenerateToken(kind string) (token, prefix string, err error) {
	buf := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	body := hex.EncodeToString(buf)
	token = kind + body
	prefix = kind + body[:prefixDisplayChars]
	return token, prefix, nil
}

// HashToken returns the hex SHA-256 of a token. This is what is stored; the
// token itself is shown once and never persisted.
//
// A single SHA-256 round (rather than a slow KDF) is correct here and not a
// weakness: the input is 192 bits of uniform randomness, so there is no
// low-entropy guessing space for an attacker to grind, which is the threat a
// slow KDF exists to defeat. It is also what makes lookup O(1) on an index.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// TokenPrefixOf extracts the display prefix from a token, so authentication can
// log "which key was used" without logging the secret.
func TokenPrefixOf(token string, kind string) string {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, kind) || len(token) < len(kind)+prefixDisplayChars {
		return ""
	}
	return token[:len(kind)+prefixDisplayChars]
}

/* -------------------------------------------------------------------------- */
/* Password hashing                                                           */
/* -------------------------------------------------------------------------- */

// pbkdf2Iterations is the work factor for password hashing. Sized so a login
// costs a few milliseconds on server hardware: enough to make offline cracking
// of a stolen hash expensive, small enough that it cannot be used as a
// denial-of-service vector against the login endpoint.
const pbkdf2Iterations = 210_000

const (
	pbkdf2SaltBytes = 16
	pbkdf2KeyBytes  = 32
)

// HashPassword returns an encoded PBKDF2-HMAC-SHA256 hash in a self-describing
// format: "pbkdf2_sha256$<iterations>$<salt-hex>$<key-hex>".
//
// The parameters travel with the hash so the work factor can be raised later
// without invalidating existing credentials — verification reads the iteration
// count from the stored value rather than from the constant.
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyBytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// VerifyPassword reports whether a password matches an encoded hash. It returns
// false (never an error) for a malformed or empty hash, so a user row with no
// password cannot be logged into by supplying an empty password.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	var iterations int
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil || iterations <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
