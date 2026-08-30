package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSplitLines covers the line splitter (used for host parsing and
// stdout parsing — the seam where katana output used to get glued).
func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a.com\nb.com\n", []string{"a.com", "b.com"}},
		{"a.com\r\nb.com", []string{"a.com", "b.com"}},
		{"a.com\n\nb.com\n", []string{"a.com", "b.com"}},
		{"  a.com  \n\tb.com\t\n", []string{"a.com", "b.com"}},
		{"", nil},
		{"a.com", []string{"a.com"}},
	}
	for _, c := range cases {
		got := splitLines(c.in)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("splitLines(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestTokenBucketLimits ensures a fast bucket lets tokens through promptly.
func TestTokenBucketLimits(t *testing.T) {
	b := newTokenBucket(1000) // 1000 rps for a fast test
	done := make(chan struct{})
	go func() {
		b.take(10)
		b.take(10)
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("token bucket blocked too long")
	}
}

// TestUnlimitedBucketNeverBlocks: rps=0 means no throttling.
func TestUnlimitedBucketNeverBlocks(t *testing.T) {
	b := newTokenBucket(0)
	done := make(chan struct{})
	go func() {
		b.take(1000000)
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("unlimited bucket should never block")
	}
}

// TestRunBatchEmitsItems verifies a fake tool's stdout lines become Items.
func TestRunBatchEmitsItems(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake_tool")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ncat\necho 'one more'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	o := &runOptions{tool: "fake_tool", batchSize: 10, timeout: 10 * time.Second}
	out := &strings.Builder{}
	var mu sync.Mutex
	n, err := runBatch(fake, o, []string{"a.com", "b.com"}, 0, json.NewEncoder(out), &mu)
	if err != nil {
		t.Fatalf("runBatch: %v", err)
	}
	// fake echoes 2 hosts + 1 extra = 3 lines
	if n != 3 {
		t.Fatalf("got %d items, want 3", n)
	}
	if strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("expected 3 JSONL lines, got %q", out.String())
	}
	// Each line must parse as an Item with tool + batch set.
	for _, ln := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var it Item
		if err := json.Unmarshal([]byte(ln), &it); err != nil {
			t.Fatalf("bad JSON line %q: %v", ln, err)
		}
		if it.Tool != "fake_tool" {
			t.Fatalf("item tool = %q, want fake_tool", it.Tool)
		}
	}
}

// TestRunBatchTimeout: a tool that sleeps forever must be killed at timeout.
func TestRunBatchTimeout(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "sleeper")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	o := &runOptions{tool: "sleeper", batchSize: 10, timeout: 300 * time.Millisecond}
	out := &strings.Builder{}
	var mu sync.Mutex
	_, err := runBatch(fake, o, []string{"a.com"}, 0, json.NewEncoder(out), &mu)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

// TestRunBatchBinaryMissing: a missing tool returns a usable error.
func TestRunBatchBinaryMissing(t *testing.T) {
	o := &runOptions{tool: "definitely-not-a-real-binary-xyz", timeout: time.Second}
	out := &strings.Builder{}
	var mu sync.Mutex
	_, err := runBatch("/nonexistent/bin", o, []string{"a.com"}, 0, json.NewEncoder(out), &mu)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}
