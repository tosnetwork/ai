// Command software-work-executord is the root-run executor service of a
// provider host. It is the only process that opens the private containerd
// socket, and it offers local callers on an explicit uid allow-list exactly
// one operation over a Unix socket: run the frozen software-work job.
//
// It is a separate command, not a mode of software-work-execute, so that the
// long-running privileged process links only the executor, the journal and
// the artifact store: no chain resolver, RPC endpoint client, quote handling
// or protocol decoding, and no flag that names a file to read.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-ai/internal/osguard"
	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/executor"
	"github.com/tosnetwork/tos-ai/pkg/executor/containerdbackend"
	"github.com/tosnetwork/tos-ai/pkg/executorservice"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
	"golang.org/x/sys/unix"
)

// version is the release this binary was built as; a release build sets it
// with -ldflags. The commit comes from the build's own VCS stamp.
var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2

	defaultMinFreeBytes = uint64(4 << 30)
	// defaultStopGrace lets a running job reach its frozen wall clock and
	// record its outcome before a stop cancels it.
	defaultStopGrace = 200 * time.Second
	maxStopGrace     = 10 * time.Minute
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stderr))
}

type options struct {
	socket           string
	socketGID        uint32
	allowedUIDs      []uint32
	containerdSocket string
	fifoDir          string
	stateDir         string
	maxExecutions    int
	minFreeBytes     uint64
	stopGrace        time.Duration
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	parsed, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	logger := log.New(stderr, "", 0)
	if err := serve(ctx, parsed, logger.Printf, notifyReady); err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	return exitOK
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	flags := flag.NewFlagSet("software-work-executord", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var parsed options
	var allowed, group string
	flags.StringVar(&parsed.socket, "socket", "", "service socket to create, inside a directory owned by this process")
	flags.StringVar(&group, "socket-gid", "", "numeric gid given access to the service socket")
	flags.StringVar(&allowed, "allow-uids", "", "comma-separated numeric uids that may call the service")
	flags.StringVar(&parsed.containerdSocket, "containerd-socket", "", "private containerd socket")
	flags.StringVar(&parsed.fifoDir, "fifo-dir", "", "private FIFO directory")
	flags.StringVar(&parsed.stateDir, "state-dir", "", "persistent private state directory (journal, artifacts)")
	flags.IntVar(&parsed.maxExecutions, "max-executions", executorservice.DefaultMaxExecutions,
		fmt.Sprintf("jobs run at once (1-%d)", executorservice.MaxExecutionsHard))
	flags.Uint64Var(&parsed.minFreeBytes, "min-free-bytes", defaultMinFreeBytes,
		"free bytes the state filesystem must keep for a new job to be accepted")
	flags.DurationVar(&parsed.stopGrace, "stop-grace", defaultStopGrace,
		"how long a stop waits for running jobs to record their outcome")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected argument")
	}
	for _, path := range []string{parsed.socket, parsed.containerdSocket, parsed.fifoDir, parsed.stateDir} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return options{}, errors.New("--socket, --containerd-socket, --fifo-dir and --state-dir must be canonical absolute paths")
		}
	}
	gid, err := parseID(group)
	if err != nil {
		return options{}, errors.New("--socket-gid must be one canonical numeric gid")
	}
	parsed.socketGID = gid
	if parsed.allowedUIDs, err = parseUIDList(allowed); err != nil {
		return options{}, err
	}
	if parsed.maxExecutions < 1 || parsed.maxExecutions > executorservice.MaxExecutionsHard {
		return options{}, errors.New("--max-executions is outside its limits")
	}
	if parsed.minFreeBytes == 0 {
		return options{}, errors.New("--min-free-bytes must be positive")
	}
	if parsed.stopGrace <= 0 || parsed.stopGrace > maxStopGrace {
		return options{}, errors.New("--stop-grace is outside its limits")
	}
	return parsed, nil
}

// parseUIDList accepts only an explicit list of canonical numeric uids. An
// empty list, a name, a duplicate or a spelling with spaces is refused: the
// allow-list is never guessed.
func parseUIDList(value string) ([]uint32, error) {
	if value == "" {
		return nil, errors.New("--allow-uids is required: the service never accepts any local user")
	}
	fields := strings.Split(value, ",")
	if len(fields) > executorservice.MaxAllowedUIDs {
		return nil, errors.New("--allow-uids names too many uids")
	}
	seen := make(map[uint32]struct{}, len(fields))
	list := make([]uint32, 0, len(fields))
	for _, field := range fields {
		uid, err := parseID(field)
		if err != nil {
			return nil, errors.New("--allow-uids must be comma-separated canonical numeric uids")
		}
		if _, duplicate := seen[uid]; duplicate {
			return nil, errors.New("--allow-uids names a uid twice")
		}
		seen[uid] = struct{}{}
		list = append(list, uid)
	}
	return list, nil
}

// parseID parses one canonical decimal 32-bit id.
func parseID(value string) (uint32, error) {
	if value == "" || len(value) > 10 || (len(value) > 1 && value[0] == '0') {
		return 0, errors.New("not a canonical id")
	}
	var result uint64
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errors.New("not a canonical id")
		}
		// At most ten digits, so this cannot overflow 64 bits.
		result = result*10 + uint64(digit-'0')
	}
	if result > math.MaxUint32 {
		return 0, errors.New("not a canonical id")
	}
	return uint32(result), nil
}

// serve opens the executor exactly as a one-shot run of the frozen job
// does, then serves it until ctx ends. ready is called once the socket
// accepts connections.
func serve(ctx context.Context, parsed options, logf func(string, ...any), ready func() error) error {
	if err := requirePrivateOwnedDirectory(parsed.stateDir); err != nil {
		return err
	}
	limits := softwarework.FrozenV1Limits()
	backend, err := containerdbackend.Open(ctx, containerdbackend.Config{
		SocketPath: parsed.containerdSocket, Namespace: "tos-service-paid-work", Snapshotter: "overlayfs",
		Runtime: "io.containerd.runc.v2", FIFODir: parsed.fifoDir, MaxActive: parsed.maxExecutions, PolicyLimits: limits,
		ImageReference: softwarework.FrozenV1ImageReference, ImageDigest: softwarework.FrozenV1ImageDigest,
		ImagePlatform: "linux/amd64",
	})
	if err != nil {
		return err
	}
	defer backend.Close()
	bound, err := executor.NewPolicyExecutor(softwarework.FrozenV1Policy(), backend)
	if err != nil {
		return err
	}
	store, err := artifactstore.Open(filepath.Join(parsed.stateDir, "artifacts"), artifactstore.MaxObjectBytesHard)
	if err != nil {
		return err
	}
	journal, err := softwarework.OpenJournal(filepath.Join(parsed.stateDir, "journal"))
	if err != nil {
		return err
	}
	defer journal.Close()
	server, err := executorservice.NewServer(executorservice.Config{
		AllowedUIDs: parsed.allowedUIDs, Executor: bound, Store: store, Journal: journal, Ready: backend.CheckReady,
		Identity: buildIdentity(), MaxExecutions: parsed.maxExecutions,
		MinFreeBytes: parsed.minFreeBytes, FreeBytes: func() (uint64, error) { return freeBytes(parsed.stateDir) },
		Logf: logf,
	})
	if err != nil {
		return err
	}
	listener, err := executorservice.Listen(parsed.socket, parsed.socketGID)
	if err != nil {
		return err
	}
	stopped := make(chan error, 1)
	go func() {
		<-ctx.Done()
		grace, cancel := context.WithTimeout(context.Background(), parsed.stopGrace)
		defer cancel()
		stopped <- server.Shutdown(grace)
	}()
	if ready != nil {
		if err := ready(); err != nil {
			logf("readiness notification failed: %v", err)
		}
	}
	logf("serving: version=%s commit=%s", buildIdentity().Version, buildIdentity().Commit)
	if err := server.Serve(listener); err != nil {
		_ = listener.Close()
		return err
	}
	if err := <-stopped; err != nil {
		return errors.New("stopped before every running job recorded its outcome")
	}
	return nil
}

func buildIdentity() executorservice.Identity {
	identity := executorservice.Identity{Version: version, Commit: "unknown"}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return identity
	}
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			identity.Commit = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if modified && identity.Commit != "unknown" {
		identity.Commit += "-modified"
	}
	return identity
}

// freeBytes is the space an unprivileged writer could still use on the
// filesystem holding path.
func freeBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil || stat.Bsize <= 0 {
		return 0, errors.New("measure state filesystem free space")
	}
	blockSize := uint64(stat.Bsize)
	if stat.Bavail > math.MaxUint64/blockSize {
		return math.MaxUint64, nil
	}
	return stat.Bavail * blockSize, nil
}

// requirePrivateOwnedDirectory refuses a state directory another user could
// read, replace or redirect.
func requirePrivateOwnedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !osguard.CurrentUserOwns(info) {
		return errors.New("state directory must be private and owned")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("state directory path contains a symlink")
	}
	return nil
}

// notifyReady tells a supervising service manager that the socket accepts
// connections. Without one it does nothing.
func notifyReady() error {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return nil
	}
	if name[0] == '@' {
		name = "\x00" + name[1:]
	} else if !filepath.IsAbs(name) {
		return errors.New("unsupported notification socket")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return errors.New("connect to the notification socket")
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		return errors.New("write to the notification socket")
	}
	return nil
}
