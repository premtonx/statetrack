// Package mcp implements a Model Context Protocol server over JSON-RPC 2.0.
//
// # Why the protocol lives here and not in the API layer
//
// The same tool surface has to be reachable two ways: over HTTP
// (`POST /api/v1/mcp`) for a hosted MCP client, and over stdio for a desktop
// client like Cursor or Claude Desktop that launches a local process. Those two
// differ only in their transport and their authentication, so the framing, the
// method dispatch, the tool definitions and the argument validation live here,
// and the two entry points supply a Backend.
//
// # What a Backend is
//
// The server never touches the database, the network or any storage. Every tool
// resolves through the Backend interface, which is the one seam that lets a test
// exercise the whole protocol without a Postgres instance, and lets the stdio
// binary reuse the identical dispatch while talking to a remote server over
// HTTP. That matters more than it sounds: if the two entry points had their own
// copies of the tool logic, a client would get different answers depending on
// how it connected, and the difference would only be noticed during an incident.
//
// # Auth
//
// This package does not authenticate anything. It sees a principal's scopes as a
// plain slice and enforces them per tool; resolving a credential to a principal
// is the transport's job, because the HTTP entry point has an API key and the
// stdio entry point has whatever it was configured with. Keeping auth out of
// here is what stops the protocol from growing a second, divergent auth path.
package mcp

import (
	"encoding/json"
	"fmt"
)

// JSONRPCVersion is the only protocol version this server speaks. It is
// emitted on every response, including errors, because a client that receives a
// malformed error has no other way to tell the response apart from a random
// HTTP body.
const JSONRPCVersion = "2.0"

// ProtocolVersion is the MCP revision advertised by `initialize`. A client that
// requires a newer revision will fall back or refuse, which is the correct
// behaviour: silently serving an older revision is how a client ends up relying
// on a field the server does not send.
const ProtocolVersion = "2024-11-05"

// ServerName identifies this implementation in the `initialize` result, which
// desktop clients display in their MCP server list.
const ServerName = "statetrack"

// ServerVersion is echoed to clients and appears in their logs, so a support
// request can name the build.
const ServerVersion = "1.0.0"

// JSON-RPC 2.0 error codes. The reserved range is fixed by the specification;
// -32000 to -32099 is implementation-defined and used here for the MCP-specific
// conditions that are not transport errors.
const (
	// CodeParseError means the payload was not valid JSON at all.
	CodeParseError = -32700
	// CodeInvalidRequest means the JSON was valid but not a JSON-RPC request.
	CodeInvalidRequest = -32600
	// CodeMethodNotFound means the method name is not one this server serves.
	CodeMethodNotFound = -32601
	// CodeInvalidParams means the method's arguments failed validation. This is
	// the code a tool-call schema violation returns, and the message names the
	// offending field so a model can correct itself rather than retrying blindly.
	CodeInvalidParams = -32602
	// CodeInternalError means the backend failed. The message is deliberately
	// generic at this code and the detail is carried in the tool result's text,
	// because an internal error is not the caller's fault to fix.
	CodeInternalError = -32603
	// CodeForbidden means the caller's credential lacks the scope a tool needs.
	// It is deliberately distinct from invalid-params: "you may not do this" and
	// "you asked wrongly" are different problems for a user to resolve.
	CodeForbidden = -32000
	// CodeNotFound means the referenced resource does not exist in this org.
	CodeNotFound = -32001
)

// Request is a JSON-RPC 2.0 request or notification.
//
// ID is a raw message rather than a string because the specification allows a
// number, a string or null, and a client that sends a numeric id must get that
// number back verbatim. Decoding it into a string would break id matching in
// every client that uses numbers, which is most of them.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request expects no response.
//
// A JSON-RPC notification omits the id. MCP uses notifications for
// fire-and-forget messages (`notifications/initialized`, cancellation), and
// replying to one is a protocol violation that some clients treat as a fatal
// framing error, so this must be checked before any response is written.
func (r Request) IsNotification() bool { return len(r.ID) == 0 }

// Response is a JSON-RPC 2.0 response. Exactly one of Result or Error is set.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// Data carries structured detail. For an invalid-params error it names the
	// offending field and the constraint, which is what lets a model repair its
	// own call instead of guessing.
	Data any `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("mcp error %d: %s", e.Code, e.Message) }

// NewError builds an error object.
func NewError(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// NewFieldError builds an invalid-params error that names the offending field,
// so a model can correct itself from the message alone.
func NewFieldError(field, format string, args ...any) *Error {
	return &Error{
		Code:    CodeInvalidParams,
		Message: fmt.Sprintf(format, args...),
		Data:    map[string]string{"field": field},
	}
}

// AsError converts any error into a JSON-RPC error object, preserving an
// *Error that already carries a code and wrapping anything else as an internal
// error.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		return e
	}
	return NewError(CodeInternalError, "%s", err.Error())
}

/* -------------------------------------------------------------------------- */
/* MCP result shapes                                                          */
/* -------------------------------------------------------------------------- */

// Content is one block of a tool result. MCP defines image, audio and embedded
// resource blocks; this server only ever produces text, because every tool
// answers with a document or a table.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// TextContent builds a single text block.
func TextContent(text string) []Content {
	return []Content{{Type: "text", Text: text}}
}

// ToolResult is the result of `tools/call`.
//
// Both Content and StructuredContent are populated. Content is what every MCP
// client understands (and what a model reads); StructuredContent is the typed
// payload a client that supports it can render as a table or a diff view rather
// than parsing prose. Emitting both means a plain client loses nothing and a
// rich one gains the structure, without the two ever disagreeing — they are
// generated from the same value.
type ToolResult struct {
	Content           []Content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	// IsError marks a tool that ran but failed (a missing event, an unreachable
	// provider). The protocol distinguishes this from a JSON-RPC error: an
	// isError result is a normal response the model should read and reason
	// about, whereas a JSON-RPC error is a protocol failure it should not.
	IsError bool `json:"isError,omitempty"`
}

// ErrorResult builds a tool result that reports a failure the model can act on.
func ErrorResult(err error) ToolResult {
	return ToolResult{
		Content: TextContent(err.Error()),
		IsError: true,
	}
}

// ErrorResponse wraps an error object as a standalone JSON-RPC response with a
// null id, which is what the specification requires when the failure is in the
// request itself (a parse error, an unreadable body) and no id could be
// recovered. The HTTP transport uses this so even a malformed body gets a
// well-formed JSON-RPC error rather than an HTML error page.
func ErrorResponse(err *Error) Response {
	return Response{JSONRPC: JSONRPCVersion, ID: json.RawMessage("null"), Error: err}
}
