package mcpprovider

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
)

// Deployment is what the MCP server checks before it starts (spec section
// 2.3). The agent cannot see these from its side; they are checked here,
// where the developer account runs.
type Deployment struct {
	// Environ is the server's environment.
	Environ []string
	// VaultEnvs name environment variables that hold the vault credential
	// besides VAULT_URL: the rail configuration's vault_url_env.
	VaultEnvs []string
	// AgentSocket is the agent socket, which the custody account owns.
	AgentSocket string
	// AgentStateDir and RailConfig are the agent's state directory and the
	// rail configuration, which this account must not be able to open.
	AgentStateDir string
	RailConfig    string
	// UID is this process's effective uid.
	UID uint32
}

// Deployment refusals.
var (
	ErrVaultInEnvironment = errors.New("a vault credential variable is set in the MCP server's environment; custody " +
		"credentials must never reach the developer account")
	ErrStateReadable = errors.New("the MCP server can open the provider agent's state directory; the agent must run " +
		"as a separate custody account")
	ErrRailReadable = errors.New("the MCP server can open the rail configuration; it must belong to the custody " +
		"account and be private to it")
	ErrUnchecked = errors.New("the provider agent's state directory or the rail configuration cannot be checked; " +
		"name the real paths")
	ErrRunsAsCustody = errors.New("the MCP server runs as the account that owns the agent socket; it must run as " +
		"the developer account")
	ErrSocketMissing = errors.New("the agent socket is not a socket")
)

// CheckDeployment refuses a deployment in which the developer account can
// reach custody: a vault credential in the environment, a state directory
// or rail configuration it can open, or a server running as the account
// that owns the agent socket.
func CheckDeployment(d Deployment) error {
	names := append([]string{"VAULT_URL"}, d.VaultEnvs...)
	for _, entry := range d.Environ {
		for _, name := range names {
			if name != "" && strings.HasPrefix(entry, name+"=") {
				return ErrVaultInEnvironment
			}
		}
	}
	for _, path := range []string{d.AgentSocket, d.AgentStateDir, d.RailConfig} {
		if !filepath.IsAbs(path) {
			return errors.New("the agent socket, the agent state directory and the rail configuration must be " +
				"absolute paths")
		}
	}
	if err := closed(d.AgentStateDir, ErrStateReadable); err != nil {
		return err
	}
	if err := closed(d.RailConfig, ErrRailReadable); err != nil {
		return err
	}
	owner, err := agentsocket.SocketOwner(d.AgentSocket)
	if err != nil {
		return ErrSocketMissing
	}
	if owner == d.UID {
		return ErrRunsAsCustody
	}
	return nil
}

// closed requires that this account cannot open path: only a permission
// refusal passes. A missing path cannot be checked and is refused too.
func closed(path string, readable error) error {
	file, err := os.Open(path)
	switch {
	case err == nil:
		return errors.Join(readable, file.Close())
	case errors.Is(err, fs.ErrPermission):
		return nil
	}
	return ErrUnchecked
}
