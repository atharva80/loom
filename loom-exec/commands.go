// loom-exec command implementations (enum / resolve / probe / urls / scan / full).
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// binary resolution — prefer ~/go/bin (Go toolchain) over PATH.
// Python's httpx CLI shadows ProjectDiscovery's httpx in PATH (the same
// bug loom fixed in Python); resolving to ~/go/bin/<tool> avoids it.
// ---------------------------------------------------------------------------

// resolveBin finds a tool binary: $LOOM_EXEC_TOOL_<NAME> env override,
// then ~/go/bin/<name>, then PATH.
func resolveBin(name string) (string, error) {
	envKey := "LOOM_EXEC_TOOL_" + strings.ToUpper(name)
	if v := os.Getenv(envKey); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v, nil
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, "go", "bin", name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath(name)
}

// ---------------------------------------------------------------------------
// enum — subdomain enumeration (subfinder + assetfinder + amass)
// ---------------------------------------------------------------------------

// enumTools returns the passive enumeration commands for a domain.
func enumTools(domain string) [][]string {
	return [][]string{
		{"subfinder", "-silent", "-d", domain, "-timeout", "30"},
		{"assetfinder", "-subs-only", domain},
	}
}

// enumToolsAll includes slow sources (amass) that may take minutes.
// These run last and can be skipped with --fast.
func enumToolsAll(domain string) [][]string {
	return append(enumTools(domain),
		[]string{"amass", "enum", "-passive", "-d", domain, "-timeout", "45"})
}

// cmdEnum runs passive subdomain enumeration against a domain.
func cmdEnum(domain string, concurrency int, outPath string, fast bool) {
	fmt.Fprintf(os.Stderr, "loom-exec: enum %s (concurrency=%d, fast=%v)\n",
		domain, concurrency, fast)
	start := time.Now()

	tools := enumTools(domain)
	if !fast {
		tools = enumToolsAll(domain)
	}

	var all []string
	for _, t := range tools {
		name := t[0]
		bin, err := resolveBin(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loom-exec:   %s not found, skipping\n", name)
			continue
		}
		fmt.Fprintf(os.Stderr, "loom-exec:   running %s\n", name)
		// Per-tool timeout: one slow source (amass) must not hang enum.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, bin, t[1:]...)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "loom-exec:   %s: %v\n", name, err)
			continue
		}
		all = append(all, splitLines(string(out))...)
	}

	uniq := uniqueLines(all)
	sort.Strings(uniq)

	fmt.Fprintf(os.Stderr, "loom-exec: enum %s -> %d unique subdomains in %s\n",
		domain, len(uniq), time.Since(start).Round(time.Millisecond))
	writeLines(outPath, uniq)
}

// ---------------------------------------------------------------------------
// resolve — DNS resolution via dnsx
// ---------------------------------------------------------------------------

func cmdResolve(hostsFile string, concurrency int, outPath string) {
	hosts := readFileLines(hostsFile)
	if len(hosts) == 0 {
		fail("no hosts in %s", hostsFile)
	}
	fmt.Fprintf(os.Stderr, "loom-exec: resolve %d hosts (concurrency=%d)\n",
		len(hosts), concurrency)

	batches := chunk(hosts, 50)
	vals := collectValues(batches, concurrency, 0, func(batch []string, bi int) ([]string, error) {
		bin, err := resolveBin("dnsx")
		if err != nil {
			return nil, err
		}
		cmd := exec.Command(bin, "-silent", "-resp", "-a", "-cname", "-l", "-")
		cmd.Stderr = os.Stderr
		stdin, _ := cmd.StdinPipe()
		go func() {
			defer stdin.Close()
			for _, h := range batch {
				fmt.Fprintln(stdin, h)
			}
		}()
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("dnsx batch %d: %v", bi, err)
		}
		// dnsx -resp outputs "host [A] ip" — strip to bare hostname so
		// downstream (probe/httpx) gets clean input.
		var hosts []string
		for _, l := range splitLines(string(out)) {
			h := l
			if i := strings.Index(h, " ["); i > 0 {
				h = h[:i]
			}
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		return hosts, nil
	})

	fmt.Fprintf(os.Stderr, "loom-exec: resolve -> %d resolved lines\n", len(vals))
	writeLines(outPath, vals)
}

// ---------------------------------------------------------------------------
// probe — HTTP probing via httpx
// ---------------------------------------------------------------------------

func cmdProbe(hostsFile string, concurrency int, outPath string, rps float64) {
	hosts := readFileLines(hostsFile)
	if len(hosts) == 0 {
		fail("no hosts in %s", hostsFile)
	}
	fmt.Fprintf(os.Stderr, "loom-exec: probe %d hosts (concurrency=%d)\n",
		len(hosts), concurrency)

	batches := chunk(hosts, 100)
	vals := collectValues(batches, concurrency, rps, func(batch []string, bi int) ([]string, error) {
		bin, err := resolveBin("httpx")
		if err != nil {
			return nil, err
		}
		// httpx reads hosts from stdin automatically when piped.
		// NOTE: do NOT pass "-l -" — httpx treats it as a literal
		// filename and errors "[FTL] No input provided" (found live
		// on vulnweb; same bug loom fixed in Python).
		cmd := exec.Command(bin, "-silent", "-no-color", "-timeout", "8",
			"-retries", "1")
		cmd.Stderr = os.Stderr
		stdin, _ := cmd.StdinPipe()
		go func() {
			defer stdin.Close()
			for _, h := range batch {
				fmt.Fprintln(stdin, h)
			}
		}()
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("httpx batch %d: %v", bi, err)
		}
		return splitLines(string(out)), nil
	})

	fmt.Fprintf(os.Stderr, "loom-exec: probe -> %d live hosts\n", len(vals))
	writeLines(outPath, vals)
}

// ---------------------------------------------------------------------------
// urls — URL mining via gau + waybackurls + katana
// ---------------------------------------------------------------------------

func cmdUrls(hostsFile string, concurrency int, outPath string) {
	hosts := readFileLines(hostsFile)
	if len(hosts) == 0 {
		fail("no hosts in %s", hostsFile)
	}
	fmt.Fprintf(os.Stderr, "loom-exec: urls from %d hosts\n", len(hosts))

	var all []string
	for _, tool := range []string{"gau", "waybackurls"} {
		bin, err := resolveBin(tool)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "loom-exec:   mining %s\n", tool)
		cmd := exec.Command(bin, "--threads", fmt.Sprint(concurrency))
		cmd.Stderr = os.Stderr
		stdin, _ := cmd.StdinPipe()
		go func() {
			defer stdin.Close()
			for _, h := range hosts {
				fmt.Fprintln(stdin, h)
			}
		}()
		out, err := cmd.Output()
		if err == nil {
			all = append(all, splitLines(string(out))...)
		}
	}

	// katana crawl of the live hosts (shallow, for discovery)
	if bin, err := resolveBin("katana"); err == nil {
		fmt.Fprintf(os.Stderr, "loom-exec:   crawling with katana\n")
		cmd := exec.Command(bin, "-silent", "-depth", "2", "-jc",
			"-timeout", "8", "-concurrency", fmt.Sprint(concurrency))
		cmd.Stderr = os.Stderr
		stdin, _ := cmd.StdinPipe()
		go func() {
			defer stdin.Close()
			for _, h := range hosts {
				fmt.Fprintln(stdin, h)
			}
		}()
		out, err := cmd.Output()
		if err == nil {
			all = append(all, splitLines(string(out))...)
		}
	}

	var uniq []string
	for _, u := range all {
		u = strings.TrimSpace(u)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		uniq = append(uniq, u)
	}
	uniq = uniqueLines(uniq)
	sort.Strings(uniq)

	fmt.Fprintf(os.Stderr, "loom-exec: urls -> %d unique URLs\n", len(uniq))
	writeLines(outPath, uniq)
}

// ---------------------------------------------------------------------------
// scan — nuclei with tech-aware tag selection
// ---------------------------------------------------------------------------

// scanTags is the DEFAULT template set — cheap, high-signal, finishes in
// minutes not days. cve alone is 4410 templates (the 82h lesson from
// 2026-08-30: 768 URLs x 7000 templates = 5.9M requests) — opt-in via
// --tags cve or --all-templates.
var scanTags = "exposure,misconfig,takeover,default-login"

func cmdScan(urlsFile string, concurrency int, outPath string, rps float64,
	allTemplates bool) {
	urls := readFileLines(urlsFile)
	if len(urls) == 0 {
		fail("no urls in %s", urlsFile)
	}
	fmt.Fprintf(os.Stderr, "loom-exec: scan %d urls (concurrency=%d, tags=%s)\n",
		len(urls), concurrency, scanTags)
	if allTemplates {
		fmt.Fprintf(os.Stderr,
			"loom-exec: WARNING --all-templates: multi-hour scan on large lists (82h lesson). Use tags.\n")
	}

	batches := chunk(urls, 50)

	var mu sync.Mutex
	var total int
	start := time.Now()

	jobCh := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bi := range jobCh {
				batch := batches[bi]
				bin, err := resolveBin("nuclei")
				if err != nil {
					fmt.Fprintf(os.Stderr, "loom-exec: nuclei not found\n")
					return
				}
				tmp, _ := os.CreateTemp("", "loom-scan-*.txt")
				for _, u := range batch {
					fmt.Fprintln(tmp, u)
				}
				tmp.Close()
				args := []string{"-l", tmp.Name(),
					"-jsonl", "-silent",
					"-severity", "medium,high,critical",
					"-rl", fmt.Sprint(rps),
					"-c", fmt.Sprint(concurrency),
				}
				if !allTemplates {
					args = append(args, "-tags", scanTags)
				}
				cmd := exec.Command(bin, args...)
				cmd.Stderr = os.Stderr
				out, err := cmd.Output()
				os.Remove(tmp.Name())
				if err != nil {
					fmt.Fprintf(os.Stderr, "loom-exec: nuclei batch %d: %v\n", bi, err)
					continue
				}
				lines := splitLines(string(out))
				mu.Lock()
				total += len(lines)
				mu.Unlock()
				for _, l := range lines {
					fmt.Fprintln(os.Stdout, l)
				}
			}
		}()
	}
	go func() {
		for i := range batches {
			jobCh <- i
		}
		close(jobCh)
	}()
	wg.Wait()

	fmt.Fprintf(os.Stderr, "loom-exec: scan -> %d findings in %s\n",
		total, time.Since(start).Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// full — the overnight pipeline
// ---------------------------------------------------------------------------

func cmdFull(domain string, workdir string, concurrency int) {
	if workdir == "" {
		workdir = "."
	}
	os.MkdirAll(workdir, 0o755)
	start := time.Now()
	fmt.Fprintf(os.Stderr, "loom-exec: FULL overnight recon on %s -> %s\n", domain, workdir)

	subsFile := filepath.Join(workdir, "subdomains.txt")
	fmt.Fprintf(os.Stderr, "\n[1/5] enum %s\n", domain)
	cmdEnum(domain, concurrency, subsFile, false)

	resolvedFile := filepath.Join(workdir, "resolved.txt")
	fmt.Fprintf(os.Stderr, "\n[2/5] resolve %d subs\n", len(readFileLines(subsFile)))
	cmdResolve(subsFile, concurrency, resolvedFile)

	liveFile := filepath.Join(workdir, "live.txt")
	fmt.Fprintf(os.Stderr, "\n[3/5] probe %d resolved\n", len(readFileLines(resolvedFile)))
	cmdProbe(resolvedFile, concurrency, liveFile, 50)

	urlsFile := filepath.Join(workdir, "urls.txt")
	fmt.Fprintf(os.Stderr, "\n[4/5] urls from %d live hosts\n", len(readFileLines(liveFile)))
	cmdUrls(liveFile, concurrency, urlsFile)

	findingsFile := filepath.Join(workdir, "findings.jsonl")
	fmt.Fprintf(os.Stderr, "\n[5/5] scan %d urls\n", len(readFileLines(urlsFile)))
	cmdScan(urlsFile, concurrency, findingsFile, 30, false)

	fmt.Fprintf(os.Stderr, "\nloom-exec: FULL done in %s\n", time.Since(start).Round(time.Second))
	fmt.Fprintf(os.Stderr, "  subdomains: %s\n", subsFile)
	fmt.Fprintf(os.Stderr, "  resolved  : %s\n", resolvedFile)
	fmt.Fprintf(os.Stderr, "  live      : %s\n", liveFile)
	fmt.Fprintf(os.Stderr, "  urls      : %s\n", urlsFile)
	fmt.Fprintf(os.Stderr, "  findings  : %s\n", findingsFile)
}

// ---------------------------------------------------------------------------
// chunk splits a slice into batches of at most n.
// ---------------------------------------------------------------------------

func chunk[T any](items []T, n int) [][]T {
	var out [][]T
	for i := 0; i < len(items); i += n {
		end := i + n
		if end > len(items) {
			end = len(items)
		}
		out = append(out, items[i:end])
	}
	return out
}
