package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The test binary doubles as a stdio MCP server with one echo tool, so the
// client is tested against a real child process over stdio.
func TestMain(m *testing.M) {
	if os.Getenv("MCP_E2E_CLIENT_FAKE_SERVER") == "1" {
		server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
		type echoInput struct {
			Value string `json:"value"`
		}
		type echoOutput struct {
			Echo  string `json:"echo"`
			Flags string `json:"flags"`
		}
		mcp.AddTool(server, &mcp.Tool{Name: "tos_buyer_echo", Description: "echo"},
			func(_ context.Context, _ *mcp.CallToolRequest, in echoInput) (*mcp.CallToolResult, echoOutput, error) {
				if in.Value == "refuse" {
					return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Refused"}}},
						echoOutput{}, nil
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echoed"}}},
					echoOutput{Echo: in.Value, Flags: strings.Join(os.Args[1:], " ")}, nil
			})
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeServer(t *testing.T) string {
	t.Helper()
	t.Setenv("MCP_E2E_CLIENT_FAKE_SERVER", "1")
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheClientCallsAToolOverStdioAndPrintsOneLine(t *testing.T) {
	server := fakeServer(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--server", server, "call", "tos_buyer_echo", `{"value":"hi"}`, "--",
		"--results-dir", "/x"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("not one line: %q", out.String())
	}
	var result Output
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	var structured struct{ Echo, Flags string }
	if err := json.Unmarshal(result.Structured, &structured); err != nil || result.IsError || structured.Echo != "hi" ||
		structured.Flags != "--results-dir /x" || result.Text != "echoed" {
		t.Fatalf("result %+v %+v %v", result, structured, err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"--server", server, "call", "tos_buyer_echo", `{"value":"refuse"}`, "--"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.IsError {
		t.Fatalf("an error result was not marked: %s", out.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"--server", server, "list", "--"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || len(result.Tools) != 1 || result.Tools[0] != "tos_buyer_echo" {
		t.Fatalf("list: %s", out.String())
	}
}

func TestTheClientRefusesMalformedRequests(t *testing.T) {
	server := fakeServer(t)
	for name, arguments := range map[string][]string{
		"no separator":            {"--server", server, "list"},
		"a relative server":       {"--server", "tos-service-buyer-mcp", "list", "--"},
		"another tool":            {"--server", server, "call", "shell_exec", `{}`, "--"},
		"arguments not an object": {"--server", server, "call", "tos_buyer_echo", `[1]`, "--"},
		"two objects":             {"--server", server, "call", "tos_buyer_echo", `{} {}`, "--"},
		"an unknown action":       {"--server", server, "delete", "--"},
	} {
		if err := run(context.Background(), arguments, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
