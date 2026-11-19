//go:build e2eexec

// Command software-work-executord-e2e is a TEST-ONLY stand-in for
// software-work-executord, for the MCP buyer end-to-end harness
// (protocol/e2e/mcp-buyer), which runs in a non-privileged container where
// containerd cannot run. It is built only with the e2eexec build tag, so no
// production build or release includes it, and it refuses to start unless
// --i-am-the-e2e-stand-in names it as such.
//
// It serves the real executorservice.Server, with its peer-uid check,
// journal and artifact store, behind the real PolicyExecutor and the frozen
// software-work policy. Only the container backend is replaced: instead of
// running the frozen job, the stand-in reads the source archive, never
// executing anything in it, and writes a deterministic, bounded log of its
// members and their SHA-256. Real sandboxed execution is covered by
// protocol/scripts/service-actor-buyer-e2e.sh with E2E_EXECUTE=1.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/artifactstore"
	"github.com/tosnetwork/ai/execution/pkg/executor"
	"github.com/tosnetwork/ai/execution/pkg/executorservice"
	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

// Bounds of the stand-in's reading of a source archive.
const (
	maxMembers   = 4096
	maxLogBytes  = 1 << 20
	maxNameBytes = 256
)

// standIn is the replaced container backend.
type standIn struct{}

// RunIsolated lists the archive's regular members with their SHA-256. It
// reads the bytes only; nothing in the archive is ever run.
func (standIn) RunIsolated(ctx context.Context, request executor.ContainerRequest, archive []byte) (executor.Result, error) {
	if request.ImageDigest != softwarework.FrozenV1ImageDigest || !request.WorkspaceArchive {
		return executor.Result{}, errors.New("the stand-in serves only the frozen software-work job")
	}
	started := time.Now()
	var log bytes.Buffer
	reader := tar.NewReader(bytes.NewReader(archive))
	members := 0
	for {
		if err := ctx.Err(); err != nil {
			return executor.Result{}, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return executor.Result{ExitCode: 1}, nil
		}
		members++
		if members > maxMembers || len(header.Name) > maxNameBytes {
			return executor.Result{ExitCode: 1}, nil
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		sum := sha256.New()
		if _, err := io.Copy(sum, io.LimitReader(reader, header.Size)); err != nil {
			return executor.Result{ExitCode: 1}, nil
		}
		fmt.Fprintf(&log, "%s %s %d\n", hex.EncodeToString(sum.Sum(nil)), strconv.Quote(header.Name), header.Size)
		if log.Len() > maxLogBytes {
			return executor.Result{ExitCode: 1}, nil
		}
	}
	fmt.Fprintf(&log, "members %d\n", members)
	return executor.Result{ExitCode: 0, Output: log.Bytes(),
		Usage: executor.Usage{CPUMillis: 1, PeakMemory: 1 << 20, DiskWritten: uint64(log.Len()), Duration: time.Since(started)}}, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "software-work-executord-e2e:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	set := flag.NewFlagSet("software-work-executord-e2e", flag.ContinueOnError)
	standInFlag := set.Bool("i-am-the-e2e-stand-in", false, "required: this binary executes nothing and is for the e2e harness only")
	socket := set.String("socket", "", "absolute path of the executor socket")
	socketGID := set.Uint("socket-gid", 0, "group that may reach the socket")
	stateDir := set.String("state-dir", "", "owner-private state directory")
	allow := set.Uint("allow-uid", 0, "the one uid served")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if !*standInFlag {
		return errors.New("refusing to start: this is the e2e stand-in executor, which executes nothing; " +
			"pass --i-am-the-e2e-stand-in only in the end-to-end harness")
	}
	if *allow == 0 || *socket == "" || !filepath.IsAbs(*stateDir) {
		return errors.New("--allow-uid, --socket and an absolute --state-dir are required")
	}
	info, err := os.Lstat(*stateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("the state directory must be a private directory")
	}
	bound, err := executor.NewPolicyExecutor(softwarework.FrozenV1Policy(), standIn{})
	if err != nil {
		return err
	}
	store, err := artifactstore.Open(filepath.Join(*stateDir, "artifacts"), artifactstore.MaxObjectBytesHard)
	if err != nil {
		return err
	}
	journal, err := softwarework.OpenJournal(filepath.Join(*stateDir, "journal"))
	if err != nil {
		return err
	}
	defer journal.Close()
	allowed := uint32(*allow)
	server, err := executorservice.NewServer(executorservice.Config{
		AllowedUID: &allowed, Executor: bound, Store: store, Journal: journal,
		Ready:    func(context.Context) error { return nil },
		Identity: executorservice.Identity{Version: "e2e-stand-in", Commit: "e2e-stand-in"},
		Logf:     func(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...) },
	})
	if err != nil {
		return err
	}
	listener, err := executorservice.Listen(*socket, uint32(*socketGID))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		grace, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = server.Shutdown(grace)
	}()
	fmt.Fprintln(os.Stderr, "serving as the e2e stand-in executor: nothing is executed")
	return server.Serve(listener)
}
