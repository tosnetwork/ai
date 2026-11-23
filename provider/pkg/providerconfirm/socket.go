package providerconfirm

import (
	"errors"
	"os"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
)

// ErrSocketNotCustody reports an agent socket this account does not own.
// The provider agent runs as the custody account and creates its socket as
// that account, and the confirmer runs as the same account; a socket owned
// by anyone else is not that agent's, and a decision sent to it would reach
// a process the human did not mean to answer.
var ErrSocketNotCustody = errors.New("the agent socket is not owned by this account; run the confirmer as the " +
	"custody account that runs the provider agent, with that agent's socket")

// CheckAgentSocket refuses an agent socket path that is not a socket owned
// by this process's effective uid. The path itself is checked, never a link
// to it.
func CheckAgentSocket(path string) error {
	return checkSocketOwner(path, uint32(os.Geteuid()))
}

func checkSocketOwner(path string, uid uint32) error {
	owner, err := agentsocket.SocketOwner(path)
	if err != nil {
		return errors.Join(errors.New("the agent socket cannot be checked: it must be the provider agent's socket "+
			"itself, not a link"), err)
	}
	if owner != uid {
		return ErrSocketNotCustody
	}
	return nil
}
