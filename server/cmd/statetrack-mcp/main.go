// Command statetrack-mcp is the standalone Model Context Protocol server for
// desktop clients.
//
// # Why this is a proxy rather than a second implementation
//
// Cursor, Claude Desktop and Windsurf launch a local process and speak MCP over
// stdio. That process has no database credentials and should not have any: a
// desktop client's config file is a poor place to keep a Postgres DSN, and a
// client that bypasses the server's RBAC, org scoping and audit trail would be a
// hole in the security model rather than a feature.
//
// So this binary is a *transport adapter*: it speaks MCP over stdio to the
// client and JSON-RPC over HTTP to a statetrack-server, forwarding each request
// verbatim. Every tool call is therefore executed by the same code path, with the
// same authorization and the same data, as the hosted endpoint — which is the
// property that matters, because two implementations of a tool surface drift and
// then a client gets a different answer depending on how it connected.
//
// # Transport details
//
// The stdio transport frames messages as newline-delimited JSON, one object per
// line, with nothing else on stdout. Every diagnostic therefore goes to stderr:
// a stray log line on stdout would be read as a malformed message and could break
// the session.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	// --version and --help are the two things a person runs when a client's
	// server entry misbehaves, so they must work without any configuration.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Fprintf(os.Stderr, "statetrack-mcp %s\n", version)
			return
		case "--help", "-h", "help":
			printUsage()
			return
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "statetrack-mcp: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "statetrack-mcp %s -> %s\n", version, cfg.ServerURL)

	p := newProxy(cfg)
	if err := p.run(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "statetrack-mcp: %v\n", err)
		os.Exit(1)
	}
}

// config is resolved entirely from the environment, because that is what a
// desktop client's MCP server entry sets. A config file would be a second place
// for the same values to disagree.
type config struct {
	// ServerURL is the statetrack-server base URL.
	ServerURL string
	// APIKey authenticates every forwarded request. It must carry the read:mcp
	// scope; the server enforces that, so a key without it produces a clear
	// forbidden error rather than an empty result.
	APIKey string
	// Timeout bounds one forwarded request. The analyzer may call out to a model,
	// so the default is generous.
	Timeout time.Duration
}

func loadConfig() (config, error) {
	base := firstNonEmpty(
		os.Getenv("STATETRACK_URL"),
		os.Getenv("STATETRACK_SERVER_URL"),
		"http://localhost:8080",
	)
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return config{}, fmt.Errorf("STATETRACK_URL must be an http(s) URL, got %q", base)
	}

	key := strings.TrimSpace(os.Getenv("STATETRACK_API_KEY"))
	if key == "" {
		// Fail loudly at startup rather than on the first tool call: a client
		// surfaces a launch failure where a person can see it, whereas a
		// per-call 401 looks like the server is broken.
		return config{}, fmt.Errorf(
			"STATETRACK_API_KEY is not set. Create an API key with the read:mcp scope " +
				"in the StateTrack console (Settings → Security) and export it:\n" +
				"  $env:STATETRACK_API_KEY = 'st_live_...'   # PowerShell\n" +
				"  export STATETRACK_API_KEY=st_live_...     # bash")
	}

	return config{
		ServerURL: base + "/api/v1/mcp",
		APIKey:    key,
		// Above the server's own 45s analysis budget, so the server's reply (or
		// its fallback analysis) always wins the race and the client sees the
		// reason rather than a bare context deadline.
		Timeout: 60 * time.Second,
	}, nil
}

func printUsage() {
	fmt.Fprint(os.Stderr, `statetrack-mcp - StateTrack Model Context Protocol server (stdio)

Reads MCP requests as newline-delimited JSON on stdin and forwards each one to a
statetrack-server over HTTP. Diagnostics are written to stderr.

Environment:
  STATETRACK_URL        Server base URL. Default http://localhost:8080
  STATETRACK_API_KEY    API key carrying the read:mcp scope. Required.

Example .cursor/mcp.json:
  {
    "mcpServers": {
      "statetrack": {
        "command": "statetrack-mcp",
        "env": {
          "STATETRACK_URL": "http://localhost:8080",
          "STATETRACK_API_KEY": "st_live_..."
        }
      }
    }
  }
`)
}

// proxy forwards newline-delimited JSON-RPC messages.
type proxy struct {
	cfg    config
	client *http.Client
}

// newProxy builds a proxy with its HTTP client.
//
// The client is constructed here rather than at the call site so the timeout
// cannot be forgotten: a proxy with a nil client panics on the first request,
// which is the worst possible failure mode for a binary a desktop client
// launches silently at startup.
func newProxy(cfg config) *proxy {
	return &proxy{
		cfg: cfg,
		// The per-request context already carries a deadline from the client's
		// disconnect; this is the backstop for a server that accepts the
		// connection and then stalls.
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// run reads messages until stdin closes or the context is cancelled.
//
// It processes messages sequentially rather than concurrently. MCP stdio
// responses are correlated by id, so concurrent requests would be legal, but a
// client that pipelines is rare and in-order replies make the stderr transcript
// readable when someone is debugging why a tool call misbehaved — which is the
// only reason anyone reads this binary's output.
func (p *proxy) run(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, 1<<20)
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		line, err := readLine(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		message := bytes.TrimSpace(line)
		if len(message) == 0 {
			continue
		}

		response, err := p.forward(ctx, message)
		if err != nil {
			// A transport failure is reported to the client as a JSON-RPC error
			// so it can show a useful message and keep the session alive. Killing
			// the process would make a transient server restart look like a
			// crashed MCP server.
			fmt.Fprintf(os.Stderr, "statetrack-mcp: forward failed: %v\n", err)
			response = transportErrorResponse(message, err)
			if response == nil {
				continue
			}
		}
		if len(response) == 0 {
			// A notification the server acknowledged with no body.
			continue
		}

		// The response is written verbatim, newline-terminated. Re-encoding it
		// would risk changing the id's numeric type, which breaks id matching.
		if _, err := writer.Write(response); err != nil {
			return err
		}
		if err := writer.WriteByte('\n'); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
}

// forward posts one message and returns the raw response body.
func (p *proxy) forward(ctx context.Context, message []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.ServerURL, bytes.NewReader(message))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusAccepted:
		// An acknowledged notification: nothing to forward.
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("the server rejected the API key (HTTP 401); " +
			"check STATETRACK_API_KEY and that the key has the read:mcp scope")
	case resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("the API key is not permitted to use MCP (HTTP 403): %s",
			strings.TrimSpace(string(body)))
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("the server returned HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// transportErrorResponse builds a JSON-RPC error for a failed forward, echoing
// the request's id when one can be recovered.
//
// The id is extracted by a lenient decode rather than the protocol package's
// decoder, because this is the error path: if the request could not even be
// parsed as JSON-RPC, there is no id to echo and the client gets a null-id error
// it can display.
func transportErrorResponse(request []byte, cause error) []byte {
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(request, &envelope)

	id := envelope.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	out, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			// -32603 (internal error) is the closest standard code: the failure
			// is between this client and its backend, not in the request.
			"code":    -32603,
			"message": "statetrack-mcp could not reach the StateTrack server: " + cause.Error(),
		},
	})
	if err != nil {
		return nil
	}
	return out
}

// readLine reads one newline-delimited message.
//
// It accumulates rather than using a Scanner so a single message larger than the
// scanner's token limit is delivered intact instead of failing the session with
// "token too long".
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			if buf.Len() > 0 && err == io.EOF {
				return buf.Bytes(), nil
			}
			return nil, err
		}
		buf.Write(chunk)
		if !isPrefix {
			return buf.Bytes(), nil
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
