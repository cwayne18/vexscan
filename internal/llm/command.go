package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unicode"
)

// CommandTransport runs a locally installed CLI once per question, writing the
// prompt to its standard input and reading the reply from its standard output.
//
// This is for the tools people already have logged in -- claude, llm, a wrapper
// script around something in-house -- where the alternative is provisioning an
// API key for a machine that already has working credentials.
//
// It is the weakest of the transports and the trade is worth stating. There is
// no structured-output mode to ask for, so the reply is whatever the CLI
// decided to print and parseVerdict has to find the JSON in it; there are no
// rate-limit headers, so a provider that wants us to slow down can only say so
// by failing; and a CLI that has not been authenticated fails per call rather
// than once at startup. None of that can produce a wrong conclusion -- the
// model's output is an overlay everywhere it is used, and mined symbols are
// validated against the artifact before they matter -- so the cost is verdicts
// that do not arrive, which is visible, rather than verdicts that are wrong.
type CommandTransport struct {
	// Args is the command and its arguments, already split. Args[0] is looked
	// up on PATH.
	Args []string
}

// NewCommandTransport splits a command line and returns a transport for it.
//
// The split is done here rather than by a shell on purpose. Passing the string
// to "sh -c" would make the caller's quoting into shell syntax -- a model name
// containing a space or a dollar sign would become the user's problem, and an
// environment variable in the string would expand at a moment nobody chose.
// This handles the one thing a command line actually needs, which is quoting
// arguments that contain spaces.
func NewCommandTransport(command string) (*CommandTransport, error) {
	args, err := splitCommand(command)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, errors.New("llm command is empty")
	}
	return &CommandTransport{Args: args}, nil
}

func (t *CommandTransport) Describe() string { return "command " + t.Args[0] }

// Chat runs the command with the prompt on stdin.
//
// The prompt goes to stdin rather than onto the command line for two reasons.
// It can be several kilobytes of advisory prose, which is close enough to the
// argument-length limit to matter; and everything on a command line is visible
// in the process table to every user on the machine, which is the wrong place
// for the contents of an image someone is triaging.
func (t *CommandTransport) Chat(ctx context.Context, system, user string) (string, error) {
	cmd := exec.CommandContext(ctx, t.Args[0], t.Args[1:]...)

	// A CLI takes one prompt, not a system/user pair, so the roles collapse
	// into one document. The instructions come first because that is the order
	// the chat APIs use and the prompts were written for.
	cmd.Stdin = strings.NewReader(system + "\n\n" + user + "\n")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("llm command %q not found on PATH", t.Args[0])
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("llm command %q: %w", t.Args[0], ctx.Err())
		}
		// Not wrapped as retryable. A CLI that failed usually failed for a
		// reason repeating it does not fix -- not logged in, a flag it does not
		// have, a model it cannot see -- and the ones that are transient are
		// already retried inside the CLI's own client. A second retry layer on
		// top would turn one bad invocation into six.
		if msg := snippet(stderr.Bytes()); msg != "(empty body)" {
			return "", fmt.Errorf("llm command %q: %w: %s", t.Args[0], err, msg)
		}
		return "", fmt.Errorf("llm command %q: %w", t.Args[0], err)
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		// Silence here would parse as a verdict of "unknown", which is a real
		// answer a model can give. A command that printed nothing did not
		// answer at all, and the two must not look the same.
		return "", fmt.Errorf("llm command %q printed nothing on stdout", t.Args[0])
	}
	return out, nil
}

// splitCommand splits a command line on whitespace, honoring single and double
// quotes. It does no expansion of any kind: no globs, no variables, no
// backslash escapes outside double quotes.
func splitCommand(s string) ([]string, error) {
	var (
		args  []string
		cur   strings.Builder
		inArg bool
		quote rune
	)
	flush := func() {
		if inArg {
			args = append(args, cur.String())
			cur.Reset()
			inArg = false
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			// An empty quoted string is still an argument, so the argument
			// starts at the quote rather than at the first character in it.
			inArg = true
		case unicode.IsSpace(r):
			flush()
		default:
			inArg = true
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("llm command has an unterminated %c quote", quote)
	}
	flush()
	return args, nil
}
