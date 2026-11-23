package servicebridge

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// nodeShutdownBudget bounds how long a stopping node waits for its receiver
// socket to finish the requests in flight.
const nodeShutdownBudget = 10 * time.Second

// Serve runs an opened node until ctx ends: the receiver socket, the relay
// carrier when the node has relays, and the service duties at interval.
// started runs once everything is open and before the duties start; an
// error from it stops the node. A node stopped through ctx returns nil. The
// caller still closes the node. `tos-service-provider serve` and the
// provider agent serve a node through this one function.
func (n *Node) Serve(ctx context.Context, interval time.Duration, started func() error) error {
	if n == nil || ctx == nil {
		return errors.New("servicebridge: no node to serve")
	}
	if n.Service == nil {
		return errors.New("the node has no rail duties to serve")
	}
	server, err := OpenAgentPacketUnixServer(n.Config.ReceiverSocket, n.Receiver)
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	relayed := make(chan error, 1)
	relayCtx, stopRelay := context.WithCancel(ctx)
	defer stopRelay()
	if n.Relay != nil {
		// The relay carrier polls the node's relays, keeps redundant
		// deposits going and rotates the node's encryption keys.
		go func() { relayed <- n.Relay.Run(relayCtx) }()
	} else {
		relayed <- nil
	}
	var runErr error
	if started != nil {
		runErr = started()
	}
	if runErr == nil {
		runErr = n.Service.Run(ctx, interval)
	}
	stopRelay()
	if relayErr := <-relayed; relayErr != nil && !errors.Is(relayErr, context.Canceled) {
		runErr = errors.Join(runErr, relayErr)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), nodeShutdownBudget)
	defer cancel()
	shutdownErr := server.Shutdown(shutdown)
	serveErr := <-served
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	// A node stopped by its operator ended as asked.
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	return errors.Join(serveErr, runErr, shutdownErr)
}
