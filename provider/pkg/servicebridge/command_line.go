package servicebridge

import (
	"errors"
	"regexp"
)

// CommandLine is how this package's messages name the program that embeds
// it: the hints that tell an operator which command to run next, the name
// the program goes by in prose, and the prefix of its scratch directories.
// It changes text shown to the operator only; no schema name, wire string,
// journal or configuration field depends on it.
type CommandLine struct {
	// Service is the command the rail verbs hang from: a hint names
	// Service + " offer", Service + " resume" and so on.
	Service string
	// Buy is the program's command that buys from an offer file, or empty
	// when the program has none; `init` then prints no buyer next step.
	Buy string
	// Program is the program's name in prose.
	Program string
	// Scratch prefixes the names of the temporary directories the package
	// creates.
	Scratch string
}

// DefaultCommandLine is the command line the package names until a program
// sets its own.
func DefaultCommandLine() CommandLine {
	return CommandLine{
		Service: "openfox earning service", Buy: "openfox earning service buy", Program: "OpenFox", Scratch: "openfox",
	}
}

var (
	commandTextPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	commandScratchPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	commandLine           = DefaultCommandLine()
)

// SetCommandLine sets how messages name the embedding program. A program
// sets it once, before it runs any command. Every field except Buy is
// required; the text is bounded and plain so that it cannot break a message
// or a file name.
func SetCommandLine(value CommandLine) error {
	if !commandTextPattern.MatchString(value.Service) || !commandTextPattern.MatchString(value.Program) ||
		(value.Buy != "" && !commandTextPattern.MatchString(value.Buy)) {
		return errors.New("servicebridge: a command line name must be 1 to 64 letters, digits, spaces, dots, " +
			"underscores or hyphens, starting with a letter or digit")
	}
	if !commandScratchPattern.MatchString(value.Scratch) {
		return errors.New("servicebridge: a command line scratch prefix must be 1 to 32 lowercase letters, digits " +
			"or hyphens, starting with a letter or digit")
	}
	extensionMutex.Lock()
	defer extensionMutex.Unlock()
	commandLine = value
	return nil
}

func currentCommandLine() CommandLine {
	extensionMutex.RLock()
	defer extensionMutex.RUnlock()
	return commandLine
}

// serviceCommand is the embedding program's command for one rail verb.
func serviceCommand(verb string) string {
	return currentCommandLine().Service + " " + verb
}

// transportFlags names the `init` flags that add a packet transport. The
// fallback transport's flag is named only in a program that registered one.
func transportFlags() (list, usage string) {
	if registeredFallbackTransport() == nil {
		return "--direct-peer or --relay-url",
			"--direct-peer agent_<hex>=<socket> (the peer's Agent id and receiver socket) or --relay-url <https URL>"
	}
	return "--direct-peer, --relay-url or --messenger-socket",
		"--direct-peer agent_<hex>=<socket> (the peer's Agent id and receiver socket), --relay-url <https URL> or " +
			"--messenger-socket <socket>"
}
