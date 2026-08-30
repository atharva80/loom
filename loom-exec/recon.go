// loom-exec recon engine — subcommands that compose the fanout core.
//
// Each command is a thin wrapper that:
//   1. collects its inputs (domain, host list, URL list)
//   2. fans the tool out across batches with Go concurrency
//   3. streams JSONL items to stdout (or -out file)
//   4. prints a one-line summary to stderr
//
// Commands:
//   enum  <domain>   — subdomain enumeration (subfinder+assetfinder+amass)
//   resolve <file>   — DNS resolution via dnsx (host list -> IPs)
//   probe  <file>    — HTTP probing via httpx (host list -> live URLs)
//   urls   <file>    — URL mining via gau+waybackurls+katana
//   scan   <file>    — nuclei scan with tech-aware tags
//   full   <domain>  — enum → resolve → probe → urls → scan (overnight)

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// small shared helpers
// ---------------------------------------------------------------------------

// fail prints to stderr and exits 1.
func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "loom-exec: "+format+"\n", a...)
	os.Exit(1)
}

// readFileLines reads a file (or stdin if path == "-") into lines.
func readFileLines(path string) []string {
	var f *os.File
	var err error
	if path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			fail("open %s: %v", path, err)
		}
		defer f.Close()
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// uniqueLines dedupes preserving order.
func uniqueLines(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

// writeLines writes lines to a file (or stdout if path == "-").
func writeLines(path string, lines []string) {
	var w *os.File
	var err error
	if path == "-" {
		w = os.Stdout
	} else {
		w, err = os.Create(path)
		if err != nil {
			fail("create %s: %v", path, err)
		}
		defer w.Close()
	}
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

// collectItems runs fn over batches and returns the item Values, deduped.
// fn must return (itemCount, error) like runBatch.
func collectValues(batches [][]string, concurrency int, rps float64,
	fn func(batch []string, bi int) ([]string, error)) []string {
	type result struct {
		vals []string
		err  error
	}
	jobCh := make(chan int)
	resCh := make(chan result, len(batches))
	var workers = concurrency
	if workers < 1 {
		workers = 1
	}
	if len(batches) < workers {
		workers = len(batches)
	}
	for w := 0; w < workers; w++ {
		go func() {
			for bi := range jobCh {
				vals, err := fn(batches[bi], bi)
				resCh <- result{vals, err}
			}
		}()
	}
	go func() {
		for i := range batches {
			jobCh <- i
		}
		close(jobCh)
	}()
	var all []string
	for range batches {
		r := <-resCh
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "loom-exec: batch error: %v\n", r.err)
			continue
		}
		all = append(all, r.vals...)
	}
	return uniqueLines(all)
}

// emitJSON writes one JSON object per line to w.
func emitJSON(w *json.Encoder, obj map[string]interface{}) {
	_ = w.Encode(obj)
}

// sortedKeys is a tiny helper for stable output.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
