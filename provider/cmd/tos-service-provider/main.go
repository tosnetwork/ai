// Command tos-service-provider sells software work on the Service Actor
// rail: it establishes the node's Agent, publishes an offer, checks
// readiness, serves paid calls and withdraws revenue. It is a thin wrapper
// over provider/pkg/servicebridge and holds no key: every signature and
// send is made by the pinned tosctl under the operator's account.
//
// Every command prints JSON on standard output and diagnostics on standard
// error, and ends with one of the exit codes below, so a program that only
// runs commands can operate a provider.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

const programName = "tos-service-provider"

const usage = "usage: " + programName + " <init|offer|preflight|serve|status|pause|resume|withdraw|manifest|metadata> [flags]\n" +
	"  init       establish this node's Agent identity and write its rail configuration\n" +
	"  offer      publish the offer: Service Actor, manifest, Capability and policy\n" +
	"  preflight  check that the node is ready to admit paid work (no chain effect)\n" +
	"  serve      receive rail packets, execute admitted work and respond\n" +
	"  status     show admission, credited revenue and each request's state\n" +
	"  pause      stop admitting new requests\n" +
	"  resume     admit new requests again\n" +
	"  withdraw   withdraw the actor's credited revenue to the owner wallet\n" +
	"  manifest   build the canonical manifest of a Capability (no chain effect)\n" +
	"  metadata   print the metadata hash the actor policy must carry\n" +
	"exit codes: 0 done; 1 the command failed; 2 the arguments were refused; 3 preflight found the node not ready; " +
	"4 a preview was printed and nothing was signed or sent (run again with --yes)"

// Exit codes. They are part of the program's interface.
const (
	exitDone         = 0
	exitFailed       = 1
	exitUsage        = 2
	exitNotReady     = 3
	exitNotConfirmed = 4
)

// usageError marks an error in the arguments, as distinct from a command
// that ran and failed.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usagef(format string, arguments ...any) error {
	return &usageError{err: fmt.Errorf(format, arguments...)}
}

// errNotReady makes a failed preflight exit with its own code after the
// report was printed.
var errNotReady = errors.New("preflight: at least one required check failed")

// streams are where a command writes: the JSON result, and diagnostics.
type streams struct {
	out io.Writer
	err io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], streams{out: os.Stdout, err: os.Stderr})
	stop()
	os.Exit(code)
}

// run executes one command and returns its exit code.
func run(ctx context.Context, arguments []string, std streams) int {
	err := dispatch(ctx, arguments, std)
	if err == nil {
		return exitDone
	}
	fmt.Fprintln(std.err, programName+":", err)
	return exitCode(err)
}

// exitCode is the exit code of a command that ended with err.
func exitCode(err error) int {
	var refused *usageError
	switch {
	case err == nil:
		return exitDone
	case errors.As(err, &refused):
		return exitUsage
	case errors.Is(err, errNotReady):
		return exitNotReady
	case errors.Is(err, servicebridge.ErrConfirmationRequired):
		return exitNotConfirmed
	}
	return exitFailed
}

type command func(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error

var commands = map[string]command{
	"init": runInit, "offer": runOffer, "preflight": runPreflight, "serve": runServe, "status": runStatus,
	"pause": runPause, "resume": runResume, "withdraw": runWithdraw, "manifest": runManifest, "metadata": runMetadata,
}

func dispatch(ctx context.Context, arguments []string, std streams) error {
	if len(arguments) == 0 {
		return usagef("%s", usage)
	}
	verb, rest := arguments[0], arguments[1:]
	if verb == "help" || verb == "-h" || verb == "--help" {
		fmt.Fprintln(std.out, usage)
		return nil
	}
	handler, known := commands[verb]
	if !known {
		return usagef("unknown command %q\n%s", verb, usage)
	}
	// The messages of the library name this program's commands.
	if err := servicebridge.SetCommandLine(servicebridge.CommandLine{
		Service: programName, Program: programName, Scratch: programName,
	}); err != nil {
		return err
	}
	set := flag.NewFlagSet(programName+" "+verb, flag.ContinueOnError)
	set.SetOutput(std.err)
	return handler(ctx, set, rest, std)
}

// parse parses a command's flags. It reports done when help was asked for
// and printed. A positional argument, a malformed flag and a missing
// required flag are usage errors.
func parse(set *flag.FlagSet, arguments []string, required ...string) (done bool, err error) {
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, nil
		}
		return false, &usageError{err: err}
	}
	if set.NArg() > 0 {
		return false, usagef("%s takes no positional argument, got %q", set.Name(), set.Arg(0))
	}
	given := givenFlags(set)
	var missing []string
	for _, name := range required {
		if !given[name] {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return false, usagef("required flag(s) %s not set", strings.Join(missing, ", "))
	}
	return false, nil
}

// givenFlags lists the flags the command line set.
func givenFlags(set *flag.FlagSet) map[string]bool {
	given := map[string]bool{}
	set.Visit(func(entry *flag.Flag) { given[entry.Name] = true })
	return given
}

// maxRepeats bounds how often one repeatable flag may be given; every list
// the library takes is far shorter.
const maxRepeats = 64

// listFlag registers a flag that may be repeated and collects its values.
func listFlag(set *flag.FlagSet, target *[]string, name, usage string) {
	set.Func(name, usage, func(value string) error {
		if value == "" {
			return errors.New("the value is empty")
		}
		if len(*target) >= maxRepeats {
			return fmt.Errorf("given more than %d times", maxRepeats)
		}
		*target = append(*target, value)
		return nil
	})
}

func railConfigFlag(set *flag.FlagSet, path *string) {
	set.StringVar(path, "rail-config", "", "owner-private rail node configuration (JSON)")
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// loadProviderConfig reads the rail configuration of a provider node. This
// program carries packets over direct sockets and relays only: a
// configuration that names the fallback packet socket or has a chat section
// is refused with the library's errors.
func loadProviderConfig(path string) (servicebridge.NodeConfig, error) {
	config, err := servicebridge.LoadNodeConfig(path)
	if err != nil {
		return config, err
	}
	if err := checkCarriers(config); err != nil {
		return config, err
	}
	if config.Provider == nil {
		return config, errors.New("the rail configuration has no provider section")
	}
	return config, nil
}

func checkCarriers(config servicebridge.NodeConfig) error {
	if config.MessengerSocket != "" {
		return servicebridge.ErrNoFallbackTransport
	}
	if config.Chat != nil {
		return servicebridge.ErrNoRelayLane
	}
	return nil
}

// checkExistingCarriers applies the same refusal before a setup command
// touches anything. A configuration that cannot be read is left to the
// command, which reports it with what to do next.
func checkExistingCarriers(path string) error {
	config, err := servicebridge.LoadNodeConfig(path)
	if err != nil {
		return nil
	}
	return checkCarriers(config)
}
