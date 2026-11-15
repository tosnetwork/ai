package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// busyServer serves one request that blocks until release closes, so its
// Shutdown cannot finish before the context ends.
func busyServer(t *testing.T, release chan struct{}) (*http.Server, chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
	}), ReadHeaderTimeout: time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	go func() {
		response, err := http.Get("http://" + listener.Addr().String() + "/")
		if err == nil {
			response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	return server, served
}

// TestShutdownServersDrainsBoth: a failing shutdown of one server never
// skips the other, and both errors are returned.
func TestShutdownServersDrainsBoth(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	relay, relayServed := busyServer(t, release)
	metrics, metricsServed := busyServer(t, release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := shutdownServers(ctx, relay, metrics)
	if !errors.Is(err, context.Canceled) ||
		err.Error() != "shutdown: context canceled\nmetrics shutdown: context canceled" {
		t.Fatalf("shutdown error = %q, want both servers' errors", err)
	}
	// Both listeners are closed: Serve has returned on each.
	for name, served := range map[string]chan error{"relay": relayServed, "metrics": metricsServed} {
		select {
		case err := <-served:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("%s serve = %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s server was not shut down", name)
		}
	}
	// Without a metrics server only the relay is shut down.
	idle := &http.Server{ReadHeaderTimeout: time.Second}
	if err := shutdownServers(context.Background(), idle, nil); err != nil {
		t.Fatal(err)
	}
}
