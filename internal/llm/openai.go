package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPTransport talks to any endpoint that speaks OpenAI's chat/completions
// wire format.
//
// That is deliberately almost everyone: OpenAI, Anthropic's compatibility
// endpoint, Azure AI Foundry, OpenRouter, Together, Groq, and the local servers
// -- Ollama, vLLM, llama.cpp -- which is why this transport has no notion of a
// provider. It sends a system message, a user message and temperature 0, and
// reads one string back. Anything a provider offers beyond that, this package
// does not need.
type HTTPTransport struct {
	HTTP     *http.Client
	Endpoint string
	Model    string

	// Token is sent as a bearer credential when set. It is optional because
	// the local servers do not want one, and sending "Bearer " with nothing
	// after it makes some of them reject the request.
	Token string
}

func (t *HTTPTransport) Describe() string {
	if t.Model == "" {
		return t.Endpoint
	}
	return t.Model + " at " + t.Endpoint
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`

	// ResponseFormat asks for a JSON object, which is exactly what both of the
	// prompts here demand in prose. Providers that implement it stop returning
	// the markdown fences and apologetic preambles parseVerdict has to strip;
	// providers that do not implement it ignore an unknown field. Neither
	// outcome needs handling, which is why it is sent unconditionally.
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat sends one system/user exchange and returns the reply text.
func (t *HTTPTransport) Chat(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:       t.Model,
		Temperature: 0,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		ResponseFormat: &responseFormat{Type: "json_object"},
	})
	if err != nil {
		return "", err
	}

	res, raw, err := t.do(ctx, body)
	if err != nil {
		// A connection that failed is the case a retry is actually for.
		return "", &retryable{err: err}
	}

	// The reply is not always JSON: rate limiting, gateway timeouts and auth
	// failures arrive as plain text or HTML from whatever proxy produced them.
	// Decode defensively and prefer the HTTP status when the body will not
	// parse, so the error says "429" rather than "unexpected character".
	var cr chatResponse
	decodeErr := json.Unmarshal(raw, &cr)

	if res.StatusCode != http.StatusOK {
		var failure error
		if decodeErr == nil && cr.Error != nil && cr.Error.Message != "" {
			failure = fmt.Errorf("llm endpoint: %s (status %d)", cr.Error.Message, res.StatusCode)
		} else {
			failure = fmt.Errorf("llm endpoint: status %d: %s", res.StatusCode, snippet(raw))
		}
		if isRetryable(res.StatusCode) {
			return "", &retryable{err: failure, after: retryAfter(res)}
		}
		return "", failure
	}
	if decodeErr != nil {
		return "", fmt.Errorf("llm endpoint: could not parse response: %s", snippet(raw))
	}
	if cr.Error != nil && cr.Error.Message != "" {
		return "", fmt.Errorf("llm endpoint: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("llm endpoint: empty response")
	}
	return cr.Choices[0].Message.Content, nil
}

// do sends one request and returns the response (with a drained body) and the
// raw body bytes.
func (t *HTTPTransport) do(ctx context.Context, body []byte) (*http.Response, []byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if t.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.Token)
	}

	client := t.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	res, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	return res, raw, nil
}

// isRetryable reports whether an HTTP status warrants another attempt.
func isRetryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// retryAfter parses the Retry-After header into a duration. Providers send a
// delay in seconds, but the header may also be an HTTP date; both are handled.
func retryAfter(res *http.Response) time.Duration {
	if res == nil {
		return 0
	}
	v := strings.TrimSpace(res.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
