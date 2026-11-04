package mcp

import (
	"encoding/json"
)

// MetaKeyName is the `params._meta` entry a `tools/call` may carry this door's
// credential under, when SCOPYX_ACCEPT_KEY_IN_META is set.
//
// # WHY A SECOND PLACE FOR ONE CREDENTIAL
//
// TokenFuse's MCP broker forwards a call with a content type and nothing of the
// caller's, so a plane behind it never sees X-Scopyx-Key. What the broker does do
// is resolve `{{secret:NAME}}` handles anywhere in `params` from its own vault, and
// typryx took the same way in for the same reason: the agent writes the handle, the
// broker writes the value on the last hop, and the agent never holds the key at
// all. That is worth more than a relayed header. An agent holding no key cannot
// come here directly, so the broker, where a run's label is put on it, is the one
// way to this plane rather than one of two.
//
// It is the door's credential and nothing else. It is not an argument to a tool, it
// never reaches a backend, and invariant 3 is unchanged: a caller still cannot hand
// this plane a credential to present to a site.
const MetaKeyName = "scopyx/key"

// needsNoCredential reports whether body is a message that carries no fetch and
// names nobody, so a caller behind the broker may send it with no credential: the
// handshake and the tool listing, which the broker forwards bare because `_meta` is
// only injected on `tools/call`.
//
// By method and never by the absence of an id. This server dispatches on the
// method alone, so a `tools/call` with no id still fetches, and reading "no id" as
// "a notification" would make leaving out one field the way past the door.
//
// Parsed into the same type ServeHTTP decodes into, so the two cannot disagree
// about which method a hostile body names, and strictly, so a body with a second
// message after the first is one this cannot vouch for. A body that does not parse
// needs a credential: fail closed rather than guess.
func needsNoCredential(body []byte) bool {
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	switch req.Method {
	case "initialize", "tools/list", "notifications/initialized":
		return true
	}
	return false
}

// extractMetaKey returns the credential a `tools/call` carries at
// `params._meta[MetaKeyName]` and body with that one entry removed.
//
// Removed whether or not it ends up being the credential used, so nothing past the
// door (a log line, the journal, an error, a backend) can ever hold it. ok is false,
// the key empty and body returned as it came, when the message is not a `tools/call`
// or carries no such entry, or the entry is not a JSON string: a caller can never
// end up using a value that was not also stripped.
func extractMetaKey(body []byte) (key string, stripped []byte, ok bool) {
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Method != "tools/call" || len(req.Params) == 0 {
		return "", body, false
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return "", body, false
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(params["_meta"], &meta); err != nil {
		return "", body, false
	}
	raw, present := meta[MetaKeyName]
	if !present {
		return "", body, false
	}
	var k string
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", body, false
	}

	delete(meta, MetaKeyName)
	if len(meta) == 0 {
		delete(params, "_meta")
	} else {
		rebuilt, err := json.Marshal(meta)
		if err != nil {
			return "", body, false
		}
		params["_meta"] = rebuilt
	}
	rebuilt, err := json.Marshal(params)
	if err != nil {
		return "", body, false
	}
	req.Params = rebuilt
	out, err := json.Marshal(req)
	if err != nil {
		return "", body, false
	}
	return k, out, true
}
