// Package mcp is the JSON-RPC surface an agent's MCP client points at, and
// the door in front of it.
//
// The tool schemas here are the enforcement point for CLAUDE.md invariant 3,
// not merely a description of it: a field that does not exist cannot be sent.
package mcp

// Tool names. These are NOT free choices.
//
// `browse`, `fetch_url` and `web_search` are already in tokenfuse's default
// taint sources map, each mapped to the `web` label. An operator who turns the
// agent firewall on therefore gets correct labelling of this plane's output
// with no configuration and no code change over there. Any other name lands in
// `unclassified`, and a rename here would be a silent behaviour change in
// another repository.
const (
	ToolBrowse   = "browse"
	ToolFetchURL = "fetch_url"
)

// Tool is one entry in a `tools/list` answer.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema is deliberately a closed shape with `additionalProperties:
// false`, and that is the whole point of this file.
//
// A free-form header or cookie parameter would be a credential-laundering
// channel straight past the broker's DLP, which scans the arguments it
// understands and cannot read an opaque map of strings. It is also how a plane
// that refuses authenticated sessions acquires them one header at a time.
//
// So the schema carries a URL and two behaviour knobs, and refuses anything
// else at the door rather than ignoring it. Ignoring an unknown field would be
// worse than refusing: the caller believes their header was sent.
type InputSchema struct {
	Type                 string              `json:"type"`
	Properties           map[string]Property `json:"properties"`
	Required             []string            `json:"required"`
	AdditionalProperties bool                `json:"additionalProperties"`
}

// Property is one input field.
type Property struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Enum        []string `json:"enum,omitempty"`
}

// Tools is what `tools/list` answers, and it is a function rather than a
// package-level slice so a caller cannot mutate the schema of a running
// server by holding a reference to it.
func Tools() []Tool {
	return []Tool{
		{
			Name: ToolBrowse,
			Description: "Fetch and render one web page on behalf of this agent, through the " +
				"operator's governed egress path. The destination and every subresource are " +
				"decided against policy before anything leaves. The result carries what was " +
				"actually retrieved, including what was blocked and what failed, so a partial " +
				"page is visible as one rather than read as a complete answer.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"url": {
						Type:        "string",
						Description: "The http or https URL to fetch. No other scheme is accepted.",
					},
					"extract": {
						Type:        "string",
						Description: "What to return: the page's text, its HTML, or a screenshot.",
						Enum:        []string{"text", "html", "screenshot"},
					},
					"wait_for": {
						Type:        "string",
						Description: "Optional CSS selector to wait for before extracting.",
					},
				},
				Required:             []string{"url"},
				AdditionalProperties: false,
			},
		},
		{
			Name: ToolFetchURL,
			Description: "Fetch one URL without rendering it, through the operator's governed " +
				"egress path. Cheaper than browse and subject to the same policy decision.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"url": {
						Type:        "string",
						Description: "The http or https URL to fetch. No other scheme is accepted.",
					},
				},
				Required:             []string{"url"},
				AdditionalProperties: false,
			},
		},
	}
}

// forbiddenFields are the argument names this plane must never accept, whatever
// a future tool is called.
//
// Kept as data rather than left to the schemas alone because the schemas are
// the thing somebody edits, and this is what `scripts/no-caller-headers.sh`
// and the test below check them against. A rule that lives only in the thing
// it governs is a rule that leaves with it.
var forbiddenFields = []string{
	"header", "headers",
	"cookie", "cookies",
	"auth", "authorization",
	"credential", "credentials",
	"token", "bearer",
	"proxy", "proxies",
	"user_agent", "userAgent",
}

// ForbiddenFields is the list, for the gate and the tests.
func ForbiddenFields() []string { return append([]string(nil), forbiddenFields...) }
