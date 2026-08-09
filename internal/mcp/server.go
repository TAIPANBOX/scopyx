package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/TAIPANBOX/scopyx/internal/decide"
)

// Call is one tool invocation, after the door and after the schema.
//
// It is a typed struct rather than the caller's map on purpose: by the time a
// fetch sees this, every field came from a name the schema declares. A map
// would carry whatever was sent, and the field that must never exist would then
// exist as far as anything downstream could tell.
type Call struct {
	Tool    string
	URL     string
	Extract string
	WaitFor string

	// AgentID is derived from the presented credential and is empty when the
	// credential names nobody. It is never read from the request body.
	AgentID string
	RunID   string
}

// Answer is what a governed fetch produced.
type Answer struct {
	Body     []byte
	FinalURL string
	Fidelity decide.Fidelity
}

// Fetcher performs a call that has already passed the door and the schema.
//
// An interface so this package tests the surface without a policy plane, a
// resolver or a network, and so the wiring lives in `cmd` where the
// configuration is.
type Fetcher interface {
	Fetch(ctx context.Context, c Call) (Answer, error)
}

// Server is the JSON-RPC surface.
type Server struct {
	Keys    Keys
	Fetcher Fetcher

	// RunID labels this process's fetches in the record. One per process,
	// because a run is a thing an operator restarts.
	RunID string
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// JSON-RPC 2.0 codes, plus the one this server adds.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// ServeHTTP answers one JSON-RPC request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "this endpoint takes JSON-RPC over POST", http.StatusMethodNotAllowed)
		return
	}

	// The door first, before the body is even parsed. A caller that cannot
	// present a credential must not be able to reach the parser, let alone the
	// tool dispatch.
	key := r.Header.Get(ClientKeyHeader)
	if !s.Keys.Allow(key) {
		http.Error(w, "a client credential is required in "+ClientKeyHeader, http.StatusUnauthorized)
		return
	}

	var req rpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{codeParse, "the request could not be parsed: " + err.Error()}})
		return
	}
	if req.JSONRPC != "2.0" {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{codeInvalidRequest, `"jsonrpc" must be "2.0"`}})
		return
	}

	switch req.Method {
	case "initialize":
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "scopyx", "version": Version},
		}})
	case "tools/list":
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": Tools()}})
	case "tools/call":
		s.call(r.Context(), w, req, key)
	case "notifications/initialized":
		// A notification carries no id and expects no answer.
		w.WriteHeader(http.StatusNoContent)
	default:
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{codeMethodNotFound, "unknown method " + req.Method}})
	}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) call(ctx context.Context, w http.ResponseWriter, req rpcRequest, key string) {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{codeInvalidParams, "the params could not be read: " + err.Error()}})
		return
	}

	tool, ok := toolByName(p.Name)
	if !ok {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{codeMethodNotFound, "unknown tool " + p.Name}})
		return
	}

	args := map[string]any{}
	if len(p.Arguments) > 0 {
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID,
				Error: &rpcError{codeInvalidParams, "the arguments could not be read: " + err.Error()}})
			return
		}
	}
	if err := validate(tool, args); err != nil {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{codeInvalidParams, err.Error()}})
		return
	}

	c := Call{
		Tool:    tool.Name,
		URL:     str(args["url"]),
		Extract: str(args["extract"]),
		WaitFor: str(args["wait_for"]),
		// From the credential, never from the body. Invariant 6.
		AgentID: s.Keys.Identity(key),
		RunID:   s.RunID,
	}

	ans, err := s.Fetcher.Fetch(ctx, c)
	if err != nil {
		// A refusal is a RESULT, not a transport error. An MCP client that
		// receives a protocol error logs a broken server; one that receives a
		// tool result with isError shows the agent why it was refused, which is
		// the difference between the agent learning the rule and retrying
		// forever.
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"isError": true,
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
		}})
		return
	}

	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"isError": false,
		"content": []map[string]any{{"type": "text", "text": string(ans.Body)}},
		// The fidelity block travels with every answer rather than on request.
		// Invariant 5: a partial page must be visible as one, and a field the
		// caller has to ask for is a field nobody asks for.
		"structuredContent": map[string]any{
			"final_url": ans.FinalURL,
			"fidelity":  ans.Fidelity,
		},
	}})
}

// validate enforces the schema the tool publishes.
//
// This function is the reason `additionalProperties: false` means anything. A
// schema that declares a closed shape beside a server that ignores extra fields
// is the "declared but unheld" control this estate keeps finding: the document
// is correct and nothing performs it.
//
// Unknown arguments are REFUSED rather than dropped. Dropping is worse, because
// the caller believes their header was sent.
func validate(t Tool, args map[string]any) error {
	if !t.InputSchema.AdditionalProperties {
		var unknown []string
		for k := range args {
			if _, ok := t.InputSchema.Properties[k]; !ok {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf(
				"%s does not accept %s. This tool takes a URL and never a header, cookie "+
					"or credential: authenticated fetching belongs to the backend and its own "+
					"credential store", t.Name, strings.Join(unknown, ", "))
		}
	}
	for _, req := range t.InputSchema.Required {
		v, ok := args[req]
		if !ok || str(v) == "" {
			return fmt.Errorf("%s requires %q", t.Name, req)
		}
	}
	for name, prop := range t.InputSchema.Properties {
		v, ok := args[name]
		if !ok {
			continue
		}
		if len(prop.Enum) == 0 {
			continue
		}
		got := str(v)
		if got == "" {
			continue
		}
		allowed := false
		for _, e := range prop.Enum {
			if e == got {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("%s: %q must be one of %s, got %q",
				t.Name, name, strings.Join(prop.Enum, ", "), got)
		}
	}
	return nil
}

func toolByName(name string) (Tool, bool) {
	for _, t := range Tools() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Version is stamped by the build.
var Version = "dev"
