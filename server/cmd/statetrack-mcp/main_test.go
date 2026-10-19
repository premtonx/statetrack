package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestReadLineDeliversLargeMessages: a single message larger than a Scanner's
// token limit must arrive intact, because failing the session on a large
// post-mortem response would break the client mid-incident.
func TestReadLineDeliversLargeMessages(t *testing.T) {
	big := strings.Repeat("x", 512<<10)
	in := bufio.NewReader(bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","pad":"` + big + `"}` + "\n")))

	line, err := readLine(in)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if !strings.Contains(string(line), big) {
		t.Fatal("a large message was truncated")
	}
}

// TestReadLineHandlesAFileWithNoTrailingNewline: a client that closes its stdin
// after the last message must have it processed, not dropped.
func TestReadLineHandlesAFileWithNoTrailingNewline(t *testing.T) {
	in := bufio.NewReader(bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	line, err := readLine(in)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if !bytes.Contains(line, []byte("ping")) {
		t.Fatalf("line = %q", line)
	}
}

// TestProxyForwardsVerbatim is the property that makes this binary safe: the
// response must be passed through unchanged, because re-encoding could change a
// numeric id into a string and break id matching in the client.
func TestProxyForwardsVerbatim(t *testing.T) {
	const responseBody = `{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}`
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer srv.Close()

	p := newProxy(config{ServerURL: srv.URL, APIKey: "st_live_test", Timeout: 5 * time.Second})
	var out bytes.Buffer
	request := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}` + "\n"

	if err := p.run(context.Background(), strings.NewReader(request), &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotAuth != "Bearer st_live_test" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody != strings.TrimSpace(request) {
		t.Errorf("forwarded body = %q, want the request verbatim", gotBody)
	}
	if got := strings.TrimSpace(out.String()); got != responseBody {
		t.Errorf("output = %q, want the response verbatim", got)
	}
}

// TestProxySkipsAcceptedNotifications: a 202 means the server acknowledged a
// notification with no body, and writing an empty line would be a protocol
// violation the client would read as a malformed message.
func TestProxySkipsAcceptedNotifications(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	p := newProxy(config{ServerURL: srv.URL, APIKey: "k", Timeout: 5 * time.Second})
	var out bytes.Buffer
	request := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"

	if err := p.run(context.Background(), strings.NewReader(request), &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a notification produced output: %q", out.String())
	}
}

// TestProxyReportsARejectedKeyActionably: a launch failure is where a person can
// see it, so the message must name the environment variable rather than leaving
// them with a bare 401.
func TestProxyReportsARejectedKeyActionably(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := newProxy(config{ServerURL: srv.URL, APIKey: "wrong", Timeout: 5 * time.Second})
	var out bytes.Buffer
	request := `{"jsonrpc":"2.0","id":3,"method":"ping"}` + "\n"

	if err := p.run(context.Background(), strings.NewReader(request), &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	// The client must receive a well-formed JSON-RPC error carrying its own id,
	// so it can display the message and keep the session alive.
	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("output is not valid JSON: %v (%q)", err, out.String())
	}
	if resp.ID != 3 {
		t.Errorf("id = %d, want 3", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("a rejected key produced no error object")
	}
	if !strings.Contains(resp.Error.Message, "STATETRACK_API_KEY") {
		t.Errorf("the error does not name the variable to fix: %q", resp.Error.Message)
	}
}

// TestProxyReportsAForbiddenKeyDistinctly: "you may not do this" and "your
// credential is invalid" are different problems for a user to resolve.
func TestProxyReportsAForbiddenKeyDistinctly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"this credential does not carry the read:mcp scope"}`))
	}))
	defer srv.Close()

	p := newProxy(config{ServerURL: srv.URL, APIKey: "st_live_narrow", Timeout: 5 * time.Second})
	var out bytes.Buffer
	_ = p.run(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out)

	if !strings.Contains(out.String(), "read:mcp") {
		t.Errorf("the server's explanation was dropped: %q", out.String())
	}
}

// TestProxySurvivesAServerRestart: a transport failure must be reported to the
// client and the session kept alive, because killing the process would make a
// transient restart look like a crashed MCP server.
func TestProxySurvivesAServerRestart(t *testing.T) {
	// Port 1 is not listening.
	p := newProxy(config{ServerURL: "http://127.0.0.1:1/api/v1/mcp", APIKey: "k", Timeout: 2 * time.Second})
	var out bytes.Buffer

	// Two requests: both must produce a reply, proving the loop continued.
	input := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	if err := p.run(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("run returned an error instead of reporting it: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d replies, want 2 (the session must survive a failure)", len(lines))
	}
	for i, line := range lines {
		var resp struct {
			ID    int `json:"id"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("reply %d is not valid JSON: %v", i, err)
		}
		if resp.Error == nil {
			t.Errorf("reply %d is not an error", i)
		}
		if resp.ID != i+1 {
			t.Errorf("reply %d id = %d, want %d", i, resp.ID, i+1)
		}
	}
}

func TestLoadConfigRequiresAnAPIKey(t *testing.T) {
	t.Setenv("STATETRACK_API_KEY", "")
	t.Setenv("STATETRACK_URL", "http://localhost:8080")

	_, err := loadConfig()
	if err == nil {
		t.Fatal("a missing API key was accepted")
	}
	// The message must tell the operator how to fix it.
	if !strings.Contains(err.Error(), "STATETRACK_API_KEY") {
		t.Errorf("the error does not name the variable: %v", err)
	}
}

func TestLoadConfigDefaultsAndNormalizesTheURL(t *testing.T) {
	t.Setenv("STATETRACK_API_KEY", "st_live_test")
	t.Setenv("STATETRACK_URL", "http://host:8080/")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	// The trailing slash must not produce a double slash in the endpoint.
	if cfg.ServerURL != "http://host:8080/api/v1/mcp" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.Timeout <= 45*time.Second {
		t.Errorf("timeout = %s, must outlast the server's own analysis budget", cfg.Timeout)
	}
}

func TestLoadConfigRejectsANonHTTPURL(t *testing.T) {
	t.Setenv("STATETRACK_API_KEY", "st_live_test")
	t.Setenv("STATETRACK_URL", "localhost:8080")

	if _, err := loadConfig(); err == nil {
		t.Fatal("an endpoint without a scheme was accepted")
	}
}

func TestTransportErrorResponseEchoesTheID(t *testing.T) {
	// A numeric id must stay numeric.
	out := transportErrorResponse([]byte(`{"jsonrpc":"2.0","id":42,"method":"ping"}`), errTest)
	var resp struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != 42 {
		t.Errorf("id = %d, want 42", resp.ID)
	}

	// An unparseable request gets a null id rather than dropping the reply.
	out = transportErrorResponse([]byte(`not json at all`), errTest)
	if !bytes.Contains(out, []byte(`"id":null`)) {
		t.Errorf("a null id was expected for an unparseable request: %s", out)
	}
}

var errTest = &testError{"connection refused"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
