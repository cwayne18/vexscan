package main

import (
	"net/url"
	"strings"
)

// stringList is a repeatable flag that also accepts a comma-separated value,
// so `--package a --package b` and `--package a,b` mean the same thing.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func isHTTPURL(path string) bool {
	u, err := url.Parse(path)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
