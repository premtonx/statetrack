package redact

import (
	"regexp"
	"strings"
	"testing"
)

var stubRe = regexp.MustCompile(`\[REDACTED:sha256:[0-9a-f]{8}\]`)

func newTestScrubber() *Scrubber { return New([]byte("test-salt")) }

func TestStubFormatAndDeterminism(t *testing.T) {
	s := newTestScrubber()
	a := s.Stub("hunter2")
	if !regexp.MustCompile(`^\[REDACTED:sha256:[0-9a-f]{8}\]$`).MatchString(a) {
		t.Fatalf("bad stub format: %q", a)
	}
	if !IsStub(a) {
		t.Fatalf("IsStub(%q) = false", a)
	}
	if b := New([]byte("test-salt")).Stub("hunter2"); a != b {
		t.Fatalf("same salt+secret produced different stubs: %q vs %q", a, b)
	}
	if b := s.Stub("hunter3"); a == b {
		t.Fatalf("different secrets produced the same stub %q", a)
	}
	if b := New([]byte("other-salt")).Stub("hunter2"); a == b {
		t.Fatalf("different salts produced the same stub %q", a)
	}
}

func TestLineRedaction(t *testing.T) {
	s := newTestScrubber()
	st := s.Stub

	tests := []struct {
		name, in, want string
	}{
		{"env assignment", "password=hunter2", "password=" + st("hunter2")},
		{"prefixed key", "DB_PASSWORD=hunter2", "DB_PASSWORD=" + st("hunter2")},
		{"export", "export GITHUB_TOKEN=ghp_abc123", "export GITHUB_TOKEN=" + st("ghp_abc123")},
		{"yaml quoted with comment", `  db_password: "s3cr3t"  # prod`, `  db_password: "` + st("s3cr3t") + `"  # prod`},
		{"yaml single quoted", `api_key: 'k-123'`, `api_key: '` + st("k-123") + `'`},
		{"json", `  "api_key": "abc123",`, `  "api_key": "` + st("abc123") + `",`},
		{"ini passphrase with comment", "secret = correct horse battery # rotated", "secret = " + st("correct horse battery") + " # rotated"},
		{"passwd keyword", "passwd = letmein", "passwd = " + st("letmein")},
		{"prefixed passwd colon", "db_passwd: letmein", "db_passwd: " + st("letmein")},
		{"private_key keyword", "private_key=abcdef", "private_key=" + st("abcdef")},
		{"api-key dashed", "x-api-key: zzz", "x-api-key: " + st("zzz")},
		{"go short assign", "token := loadToken()", "token := " + st("loadToken()")},
		{"case insensitive", "PASSWORD: Hunter2", "PASSWORD: " + st("Hunter2")},
		{"aws secret key", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"aws_secret_access_key = " + st("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")},
		{"aws access key id", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "aws_access_key_id = " + st("AKIAIOSFODNN7EXAMPLE")},
		{"connection string", "Server=db;User Id=sa;Password=P@ss w0rd;Encrypt=true",
			"Server=db;User Id=sa;Password=" + st("P@ss w0rd") + ";Encrypt=true"},
		{"url credentials", "DATABASE_URL=postgres://app:pa55word@db:5432/app",
			"DATABASE_URL=postgres://app:" + st("pa55word") + "@db:5432/app"},
		{"query string", "url=https://x/cb?token=abc&user=bob", "url=https://x/cb?token=" + st("abc") + "&user=bob"},
		{"bearer", "Authorization: Bearer eyJhbGciOi.payload.sig", "Authorization: Bearer " + st("eyJhbGciOi.payload.sig")},
		{"web.config appSetting", `<add key="DbPassword" value="Sup3r!"/>`, `<add key="DbPassword" value="` + st("Sup3r!") + `"/>`},
		{"xml attribute", `<db password="Sup3r!" />`, `<db password="` + st("Sup3r!") + `" />`},
		{"high entropy token", "client = 8fJ2kLq9ZxP4mN7vR1tY6wB3cD5eH0aS", "client = " + st("8fJ2kLq9ZxP4mN7vR1tY6wB3cD5eH0aS")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.Line(tc.in); got != tc.want {
				t.Errorf("Line(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLineLeavesNonSecretsAlone(t *testing.T) {
	s := newTestScrubber()
	for _, in := range []string{
		"PasswordAuthentication no",
		"listen_port = 8080",
		"server_name example.com www.example.com;",
		"ExecStart=/usr/bin/nginx -g 'daemon off;'",
		"sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"id = 550e8400-e29b-41d4-a716-446655440000",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHk8Q3T5x7uVb9pZ2mN4kR6sW1yE0aJcLfGdHqXoPvBt ops@bastion",
		"path = /usr/lib/x86_64-linux-gnu/libssl.so.3",
		"password:",
		`password = ""`,
		"ops ALL=(ALL) NOPASSWD: ALL",
		"%admin ALL=(ALL) PASSWD: /usr/bin/systemctl",
		"passwd:         files systemd",
		"auth required pam_unix.so nullok try_first_pass",
		"",
	} {
		if got := s.Line(in); got != in {
			t.Errorf("Line(%q) modified a non-secret line: %q", in, got)
		}
	}
}

func TestTextPreservesLineStructure(t *testing.T) {
	s := newTestScrubber()
	in := "[database]\r\nhost = db.internal\r\npassword = hunter2\r\nport = 5432\r\n\r\n# end"
	got := s.Text(in)

	want := "[database]\r\nhost = db.internal\r\npassword = " + s.Stub("hunter2") + "\r\nport = 5432\r\n\r\n# end"
	if got != want {
		t.Fatalf("Text()\n got: %q\nwant: %q", got, want)
	}
	if strings.Count(got, "\n") != strings.Count(in, "\n") {
		t.Fatalf("line count changed")
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("secret leaked: %q", got)
	}
}

func TestTextIsIdempotent(t *testing.T) {
	s := newTestScrubber()
	in := strings.Join([]string{
		"password = correct horse battery",
		`"api_key": "abc123",`,
		"DATABASE_URL=postgres://app:pa55word@db/app",
		"token=8fJ2kLq9ZxP4mN7vR1tY6wB3cD5eH0aS",
		"AKIAIOSFODNN7EXAMPLE",
		"",
	}, "\n")
	once := s.Text(in)
	if twice := s.Text(once); twice != once {
		t.Fatalf("not idempotent\nonce:  %q\ntwice: %q", once, twice)
	}
}

const testPEM = `tls:
  key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAuA1b2c3d4e5f6g7h8i9j0kLmNoPqRsTuVwXyZ
    q1w2e3r4t5y6u7i8o9p0aSdFgHjKlZxCvBnM1234567890abcdefg
    -----END RSA PRIVATE KEY-----
  cert: /etc/ssl/cert.pem
`

func TestTextRedactsPEMBlock(t *testing.T) {
	s := newTestScrubber()
	got := s.Text(testPEM)
	gotLines := strings.Split(got, "\n")
	inLines := strings.Split(testPEM, "\n")
	if len(gotLines) != len(inLines) {
		t.Fatalf("line count changed: %d -> %d", len(inLines), len(gotLines))
	}
	stub := s.Stub("MIIEowIBAAKCAQEAuA1b2c3d4e5f6g7h8i9j0kLmNoPqRsTuVwXyZ" +
		"q1w2e3r4t5y6u7i8o9p0aSdFgHjKlZxCvBnM1234567890abcdefg")
	want := []string{
		"tls:",
		"  key: |",
		"    -----BEGIN RSA PRIVATE KEY-----",
		"    " + stub,
		"    " + stub,
		"    -----END RSA PRIVATE KEY-----",
		"  cert: /etc/ssl/cert.pem",
		"",
	}
	for i := range want {
		if gotLines[i] != want[i] {
			t.Errorf("line %d\n got: %q\nwant: %q", i, gotLines[i], want[i])
		}
	}
}

func TestTextRedactsTruncatedPEMBlock(t *testing.T) {
	s := newTestScrubber()
	in := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
	got := s.Text(in)
	if strings.Contains(got, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ") {
		t.Fatalf("truncated PEM body leaked: %q", got)
	}
	if !strings.HasPrefix(got, "-----BEGIN OPENSSH PRIVATE KEY-----\n") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("structure not preserved: %q", got)
	}
}

func TestCertificatesAreNotRedactedAsPEMKeys(t *testing.T) {
	s := newTestScrubber()
	in := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if got := s.Text(in); got != in {
		t.Fatalf("certificate modified: %q", got)
	}
}

func TestUnifiedDiff(t *testing.T) {
	s := newTestScrubber()
	in := strings.Join([]string{
		"--- a/etc/app/config.ini",
		"+++ b/etc/app/config.ini",
		"@@ -1,3 +1,3 @@",
		" [database]",
		"-password = oldsecret",
		"+password = newsecret",
		" port = 5432",
		`\ No newline at end of file`,
		"",
	}, "\n")
	want := strings.Join([]string{
		"--- a/etc/app/config.ini",
		"+++ b/etc/app/config.ini",
		"@@ -1,3 +1,3 @@",
		" [database]",
		"-password = " + s.Stub("oldsecret"),
		"+password = " + s.Stub("newsecret"),
		" port = 5432",
		`\ No newline at end of file`,
		"",
	}, "\n")
	if got := s.UnifiedDiff(in); got != want {
		t.Fatalf("UnifiedDiff()\n got: %q\nwant: %q", got, want)
	}
}

func TestUnifiedDiffKeepsMarkersOnHighEntropyLines(t *testing.T) {
	s := newTestScrubber()
	tok := "8fJ2kLq9ZxP4mN7vR1tY6wB3cD5eH0aS"
	got := s.UnifiedDiff("+" + tok + "\n")
	if want := "+" + s.Stub(tok) + "\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUnifiedDiffPEM(t *testing.T) {
	s := newTestScrubber()
	in := "@@ -0,0 +1,4 @@\n+-----BEGIN EC PRIVATE KEY-----\n+MHcCAQEEIBkg\n+AwEHoUQDQgAE\n+-----END EC PRIVATE KEY-----\n"
	stub := s.Stub("MHcCAQEEIBkgAwEHoUQDQgAE")
	want := "@@ -0,0 +1,4 @@\n+-----BEGIN EC PRIVATE KEY-----\n+" + stub + "\n+" + stub + "\n+-----END EC PRIVATE KEY-----\n"
	if got := s.UnifiedDiff(in); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestNoSecretSurvives(t *testing.T) {
	s := newTestScrubber()
	secrets := []string{"hunter2", "pa55word", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	in := "password: hunter2\nurl: mysql://root:pa55word@localhost/db\nkey_id AKIAIOSFODNN7EXAMPLE\n" +
		"export AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	got := s.Text(in)
	for _, sec := range secrets {
		if strings.Contains(got, sec) {
			t.Errorf("secret %q leaked in %q", sec, got)
		}
	}
	if n := len(stubRe.FindAllString(got, -1)); n != len(secrets) {
		t.Errorf("expected %d stubs, got %d in %q", len(secrets), n, got)
	}
}

func BenchmarkText(b *testing.B) {
	s := newTestScrubber()
	in := strings.Repeat("server_name example.com;\nlisten 443 ssl;\npassword = hunter2\n", 200)
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Text(in)
	}
}
