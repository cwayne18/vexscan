package llm

import (
	"context"
	"errors"
	"time"
)

// Transport carries one system/user exchange to a model and returns its reply
// text. It exists so the provider is a configuration choice rather than a
// compile-time one: the questions this package asks are small and the answers
// are short JSON, which every chat model can do, so nothing above this
// interface should know or care where the model runs.
//
// Implementations must not retry. Whether another attempt is worth making is
// decided in chat, from the error: an implementation that also retried would
// multiply the two policies together.
type Transport interface {
	// Chat sends the system and user messages and returns the reply text.
	Chat(ctx context.Context, system, user string) (string, error)

	// Describe names the provider for log lines and error messages, without
	// any credential in it.
	Describe() string
}

// retryable marks an error as worth another attempt, optionally carrying the
// delay the provider asked for.
//
// The alternative -- inspecting HTTP status codes in the retry loop -- only
// works for one kind of transport. A local command has no status code and
// mostly fails for reasons no retry fixes, so the transport that produced an
// error is the only thing that can say whether repeating it is sensible.
type retryable struct {
	err   error
	after time.Duration
}

func (r *retryable) Error() string { return r.err.Error() }
func (r *retryable) Unwrap() error { return r.err }

// retryHint reports whether err is retryable, and how long to wait first.
func retryHint(err error) (bool, time.Duration) {
	var r *retryable
	if errors.As(err, &r) {
		return true, r.after
	}
	return false, 0
}
