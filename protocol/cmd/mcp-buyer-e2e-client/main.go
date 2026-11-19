// Command mcp-buyer-e2e-client is the MCP client of the MCP buyer adapter's
// end-to-end harness (protocol/e2e/mcp-buyer). It starts
// tos-service-buyer-mcp as a child over stdio, exactly as an MCP client
// does, calls one tool or lists the tools, and prints one JSON line: the
// tool's structured content, whether it is an error result, and its text.
//
// It runs in the developer account and holds nothing: everything it can do
// goes through the MCP server, and through it to the agent socket.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Output is the one JSON line a call prints.
type Output struct {
	Tool       string          `json:"tool,omitempty"`
	IsError    bool            `json:"is_error"`
	Structured json.RawMessage `json:"structured,omitempty"`
	Text       string          `json:"text,omitempty"`
	Tools      []string        `json:"tools,omitempty"`
}

// maxArguments bounds the tool arguments read from the command line.
const maxArguments = 1 << 20

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-buyer-e2e-client:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, out io.Writer) error {
	set := flag.NewFlagSet("mcp-buyer-e2e-client", flag.ContinueOnError)
	server := set.String("server", "", "absolute path of tos-service-buyer-mcp")
	timeout := set.Duration("timeout", 6*time.Minute, "overall bound of one call")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	rest := set.Args()
	separator := -1
	for index, argument := range rest {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 1 {
		return errors.New("usage: mcp-buyer-e2e-client --server PATH <list|call TOOL ARGS_JSON> -- SERVER_FLAGS...")
	}
	action, serverFlags := rest[:separator], rest[separator+1:]
	if !filepath.IsAbs(*server) {
		return errors.New("--server must be an absolute path")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-buyer-e2e-client", Version: "1.0.0"}, nil)
	command := exec.CommandContext(ctx, *server, serverFlags...)
	command.Stderr = os.Stderr
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		return fmt.Errorf("the MCP server did not start: %w", err)
	}
	defer session.Close()
	result, err := perform(ctx, session, action)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(encoded))
	return err
}

// perform runs one action on a connected session.
func perform(ctx context.Context, session *mcp.ClientSession, action []string) (Output, error) {
	switch {
	case len(action) == 1 && action[0] == "list":
		listed, err := session.ListTools(ctx, nil)
		if err != nil {
			return Output{}, err
		}
		out := Output{Tools: []string{}}
		for _, tool := range listed.Tools {
			out.Tools = append(out.Tools, tool.Name)
		}
		return out, nil
	case len(action) == 3 && action[0] == "call":
		return call(ctx, session, action[1], action[2])
	}
	return Output{}, errors.New("the action is list, or call TOOL ARGS_JSON")
}

func call(ctx context.Context, session *mcp.ClientSession, tool, raw string) (Output, error) {
	if !strings.HasPrefix(tool, "tos_buyer_") || len(raw) > maxArguments {
		return Output{}, errors.New("the tool must be a tos_buyer_ tool and its arguments at most 1 MiB")
	}
	var arguments map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&arguments); err != nil || decoder.More() {
		return Output{}, errors.New("ARGS_JSON must be one JSON object")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: arguments})
	if err != nil {
		return Output{}, err
	}
	out := Output{Tool: tool, IsError: result.IsError}
	if result.StructuredContent != nil {
		if out.Structured, err = json.Marshal(result.StructuredContent); err != nil {
			return Output{}, err
		}
	}
	var parts []string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			parts = append(parts, text.Text)
		}
	}
	out.Text = strings.Join(parts, "\n")
	return out, nil
}
