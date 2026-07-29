package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// capture is a server that records the messages it was sent and replies with a
// fixed body.
type capture struct {
	srv    *httptest.Server
	calls  int32
	system []string
	user   []string
}

func newCapture(t *testing.T, reply string) *capture {
	t.Helper()
	c := &capture{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&c.calls, 1)
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("request body is not a chat request: %v", err)
		}
		for _, m := range req.Messages {
			switch m.Role {
			case "system":
				c.system = append(c.system, m.Content)
			case "user":
				c.user = append(c.user, m.Content)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

// chatReply wraps model output in the API's envelope.
func chatReply(content string) string {
	b, err := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]string{"content": content}}},
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestMineExtractsIdentifiers(t *testing.T) {
	cap := newCapture(t, chatReply(
		`{"symbols":["SSL_free_buffers"],"sonames":["libssl.so.3"],"files":["ssl/ssl_lib.c"],"note":"named one function"}`))

	c := testClient(cap.srv.URL)
	h, err := c.Mine(context.Background(), MineRequest{
		ID: "CVE-2024-4741", Ecosystem: "os", Package: "openssl",
		Summary: "Use After Free with SSL_free_buffers",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.Symbols, []string{"SSL_free_buffers"}) {
		t.Errorf("symbols = %v", h.Symbols)
	}
	if !reflect.DeepEqual(h.Sonames, []string{"libssl.so.3"}) {
		t.Errorf("sonames = %v", h.Sonames)
	}
	if h.Empty() {
		t.Error("hints report themselves empty")
	}
	// The advisory text and the package name must both reach the model: a
	// multi-package advisory names identifiers for packages other than the one
	// being checked, and the model cannot separate them without being told.
	if len(cap.user) != 1 || !strings.Contains(cap.user[0], "SSL_free_buffers") || !strings.Contains(cap.user[0], "openssl") {
		t.Errorf("user message = %q", cap.user)
	}
}

// A second lookup of the same advisory must not cost a second call: one
// advisory routinely applies to several packages across several images in a
// single run.
func TestMineCachesPerAdvisory(t *testing.T) {
	cap := newCapture(t, chatReply(`{"symbols":["png_handle_iCCP"],"sonames":[],"files":[]}`))
	c := testClient(cap.srv.URL)
	req := MineRequest{ID: "CVE-2015-8540", Ecosystem: "os", Package: "libpng", Summary: "png_handle_iCCP underflow"}

	for range 3 {
		if _, err := c.Mine(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if cap.calls != 1 {
		t.Errorf("got %d API calls, want 1", cap.calls)
	}
}

// An advisory with no text is not worth asking about, and asking anyway invites
// the model to fill the silence.
func TestMineSkipsEmptyAdvisoryText(t *testing.T) {
	cap := newCapture(t, chatReply(`{"symbols":["anything"]}`))
	c := testClient(cap.srv.URL)

	h, err := c.Mine(context.Background(), MineRequest{ID: "CVE-1", Package: "openssl"})
	if err != nil {
		t.Fatal(err)
	}
	if !h.Empty() {
		t.Errorf("got hints from an advisory with no text: %+v", h)
	}
	if cap.calls != 0 {
		t.Errorf("got %d API calls, want 0", cap.calls)
	}
}

// Mining is optional and advisory. A model that answers with prose has told us
// it found nothing it could name; failing the scan over that would let the
// advisory layer break the deterministic one.
func TestMineTreatsAnUnparseableReplyAsNothingFound(t *testing.T) {
	c := testClient(newCapture(t, chatReply("I'm sorry, I can't help with that.")).srv.URL)
	h, err := c.Mine(context.Background(), MineRequest{ID: "CVE-1", Package: "openssl", Summary: "a hole"})
	if err != nil {
		t.Fatalf("an unparseable reply is not an error: %v", err)
	}
	if !h.Empty() || h.Note == "" {
		t.Errorf("got %+v, want empty hints with a note", h)
	}
}

// Everything downstream matches these strings against a real symbol table, so
// anything that could not be an identifier is only more noise to fail to match.
func TestCleanIdentsRejectsWhatCannotBeAnIdentifier(t *testing.T) {
	got := cleanIdents([]string{
		"SSL_free_buffers",
		"`png_handle_iCCP`",       // fenced by the model
		"  libssl.so.3  ",         // padded
		"SSL_free_buffers",        // duplicate
		"CVE-2024-4741",           // an id, not a symbol -- but it does look like one
		"a",                       // too short to match anything but by accident
		"png_read_info()",         // written as a call, as models tend to
		"the vulnerable function", // prose
		"",
	})
	// CVE-2024-4741 survives: the filter is a shape check, not a parser, and an
	// id that looks like an identifier costs one symbol-table lookup that finds
	// nothing. Letting it through is cheaper than a rule that might also reject
	// a real symbol.
	want := []string{"CVE-2024-4741", "SSL_free_buffers", "libssl.so.3", "png_handle_iCCP", "png_read_info"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCleanIdentsReturnsNilWhenNothingSurvives(t *testing.T) {
	if got := cleanIdents([]string{"a", "()", "two words"}); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
