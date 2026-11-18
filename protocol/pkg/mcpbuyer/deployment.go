package mcpbuyer

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

// Deployment is what the MCP server checks before it starts (section 5.1).
type Deployment struct {
	// Environ is the server's environment.
	Environ []string
	// AgentStateDir is the buyer agent's state directory, which the server
	// must not be able to read.
	AgentStateDir string
	// AgentSocket is the agent socket, which the custody account owns.
	AgentSocket string
}

// Deployment refusals.
var (
	ErrVaultInEnvironment = errors.New("VAULT_URL is set in the MCP server's environment; custody credentials must never reach the developer account")
	ErrStateReadable      = errors.New("the MCP server can read the buyer agent's state directory; the agent must run as a separate custody account")
	ErrStateUnchecked     = errors.New("the buyer agent's state directory cannot be checked; name the agent's real state directory")
	ErrRunsAsCustody      = errors.New("the MCP server runs as the account that owns the agent socket; it must run as the developer account")
	ErrSocketMissing      = errors.New("the agent socket is not a socket")
)

// CheckDeployment refuses a deployment in which the developer account
// can reach custody: a vault credential in the environment, a readable
// agent state directory, or a server running as the custody account. The
// agent cannot see these from its side; they are checked here, where the
// developer account runs.
func CheckDeployment(d Deployment) error {
	for _, entry := range d.Environ {
		if strings.HasPrefix(entry, "VAULT_URL=") {
			return ErrVaultInEnvironment
		}
	}
	if !filepath.IsAbs(d.AgentStateDir) || !filepath.IsAbs(d.AgentSocket) {
		return errors.New("the agent state directory and socket must be absolute paths")
	}
	directory, err := os.Open(d.AgentStateDir)
	switch {
	case err == nil:
		directory.Close()
		return ErrStateReadable
	case !errors.Is(err, fs.ErrPermission):
		return ErrStateUnchecked
	}
	info, err := os.Lstat(d.AgentSocket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return ErrSocketMissing
	}
	if osguard.CurrentUserOwns(info) {
		return ErrRunsAsCustody
	}
	return nil
}
