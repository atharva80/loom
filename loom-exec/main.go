// loom-exec — Go fanout executor for loom.
//
// A dependency-free binary that runs a tool (dnsx, httpx, nuclei, ...)
// across a host list with real goroutine concurrency, token-bucket rate
// limiting, live progress stats, and structured JSONL output.
//
// Python loom calls this for the hot path instead of spawning one
// subprocess per host: here the worker pool + rate limiter live in Go,
// and the tool processes one host-batch per worker.
//
//   cat hosts.txt | loom-exec run --tool httpx --args "-silent -json" \
//       --concurrency 16 --rps 50 --out results.jsonl
//
// Output (JSONL, one object per item):
//   {"ts":..., "tool":"httpx", "batch":0, "hosts":N, "value":"...", ...}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Version stamped at build time (or via -ldflags).
var Version = "0.1.0"

// Item is one parsed output line from a tool run.
type Item struct {
	TS      float64 `json:"ts"`
	Tool    string  `json:"tool"`
	Batch   int     `json:"batch"`
	Hosts   int     `json:"hosts"`
	Value   string  `json:"value"`
	IsError bool    `json:"is_error,omitempty"`
}

// Stats is the live progress snapshot (printed to stderr by a ticker).
type Stats struct {
	Elapsed   string  `json:"elapsed"`
	DoneB     int     `json:"batches_done"`
	TotalB    int     `json:"batches_total"`
	HostsDone int     `json:"hosts_done"`
	Items     int     `json:"items"`
	Errors    int     `json:"errors"`
	RPS       float64 `json:"rps"`
}

// tokenBucket is a simple thread-safe token bucket for rate limiting.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	refill   float64 // tokens per second
	last     time.Time
}

func newTokenBucket(rps float64) *tokenBucket {
	if rps <= 0 {
		return &tokenBucket{tokens: 1e18, capacity: 1e18, refill: 1e18, last: time.Now()}
	}
	return &tokenBucket{tokens: rps, capacity: rps, refill: rps, last: time.Now()}
}

func (b *tokenBucket) take(n int) {
	if b.capacity > 1e17 {
		return // unlimited
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = minF(b.capacity, b.tokens+elapsed*b.refill)
		b.last = now
	}
	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return
	}
	need := float64(n) - b.tokens
	sleep := need / b.refill
	b.tokens = 0
	b.last = now.Add(time.Duration(sleep * float64(time.Second)))
	time.Sleep(time.Duration(sleep * float64(time.Second)))
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

type runOptions struct {
	tool        string
	argsRaw     string
	concurrency int
	rps         float64
	timeout     time.Duration
	hostsPath   string
	outPath     string
	batchSize   int
	quiet       bool
}

func parseRunArgs(args []string) (*runOptions, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := &runOptions{}
	fs.StringVar(&o.tool, "tool", "", "tool binary to run (required)")
	fs.StringVar(&o.argsRaw, "args", "", "space-separated extra args for the tool")
	fs.IntVar(&o.concurrency, "concurrency", 8, "max parallel tool processes")
	fs.Float64Var(&o.rps, "rps", 0, "global rate limit (requests/sec; 0 = unlimited)")
	fs.DurationVar(&o.timeout, "timeout", 300*time.Second, "per-batch timeout")
	fs.StringVar(&o.hostsPath, "hosts", "-", "host list file (default: stdin)")
	fs.StringVar(&o.outPath, "out", "-", "JSONL output file (default: stdout)")
	fs.IntVar(&o.batchSize, "batch", 100, "hosts per tool invocation")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress live stats on stderr")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if o.tool == "" {
		return nil, fmt.Errorf("--tool is required")
	}
	if o.concurrency < 1 {
		return nil, fmt.Errorf("--concurrency must be >= 1")
	}
	if o.batchSize < 1 {
		return nil, fmt.Errorf("--batch must be >= 1")
	}
	return o, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "loom-exec: fanout executor + recon engine for loom")
		fmt.Fprintln(os.Stderr, "usage:")
		fmt.Fprintln(os.Stderr, "  loom-exec run <flags>              fanout tool across host batches")
		fmt.Fprintln(os.Stderr, "  loom-exec enum <domain> [--out f]  subdomain enumeration")
		fmt.Fprintln(os.Stderr, "  loom-exec resolve <hosts> [--out]  DNS resolution (dnsx)")
		fmt.Fprintln(os.Stderr, "  loom-exec probe <hosts> [--out]    HTTP probing (httpx)")
		fmt.Fprintln(os.Stderr, "  loom-exec urls <hosts> [--out]     URL mining (gau/waybackurls/katana)")
		fmt.Fprintln(os.Stderr, "  loom-exec scan <urls> [--out]      nuclei scan")
		fmt.Fprintln(os.Stderr, "  loom-exec full <domain> [--dir]    full overnight pipeline")
		fmt.Fprintln(os.Stderr, "  loom-exec version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "enum":
		cmdEnumDispatch(os.Args[2:])
	case "resolve":
		cmdResolveDispatch(os.Args[2:])
	case "probe":
		cmdProbeDispatch(os.Args[2:])
	case "urls":
		cmdUrlsDispatch(os.Args[2:])
	case "scan":
		cmdScanDispatch(os.Args[2:])
	case "full":
		cmdFullDispatch(os.Args[2:])
	case "version":
		fmt.Println(Version)
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stderr, "usage: loom-exec <run|enum|resolve|probe|urls|scan|full> [flags]")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "loom-exec: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

// --- dispatch wrappers (flag parsing per command) ---

func cmdEnumDispatch(args []string) {
	fs := newFlagSet("enum")
	domain := fs.String("domain", "", "domain to enumerate (required)")
	out := fs.String("out", "-", "output file (default stdout)")
	conc := fs.Int("concurrency", 8, "parallel workers")
	fast := fs.Bool("fast", false, "skip slow sources (amass)")
	fs.Parse(args)
	if *domain == "" {
		fail("--domain is required")
	}
	cmdEnum(*domain, *conc, *out, *fast)
}

func cmdResolveDispatch(args []string) {
	fs := newFlagSet("resolve")
	hosts := fs.String("hosts", "", "hosts file (required)")
	out := fs.String("out", "-", "output file (default stdout)")
	conc := fs.Int("concurrency", 8, "parallel workers")
	fs.Parse(args)
	if *hosts == "" {
		fail("--hosts is required")
	}
	cmdResolve(*hosts, *conc, *out)
}

func cmdProbeDispatch(args []string) {
	fs := newFlagSet("probe")
	hosts := fs.String("hosts", "", "hosts file (required)")
	out := fs.String("out", "-", "output file (default stdout)")
	conc := fs.Int("concurrency", 8, "parallel workers")
	rps := fs.Float64("rps", 50, "rate limit")
	fs.Parse(args)
	if *hosts == "" {
		fail("--hosts is required")
	}
	cmdProbe(*hosts, *conc, *out, *rps)
}

func cmdUrlsDispatch(args []string) {
	fs := newFlagSet("urls")
	hosts := fs.String("hosts", "", "hosts file (required)")
	out := fs.String("out", "-", "output file (default stdout)")
	conc := fs.Int("concurrency", 8, "parallel workers")
	fs.Parse(args)
	if *hosts == "" {
		fail("--hosts is required")
	}
	cmdUrls(*hosts, *conc, *out)
}

func cmdScanDispatch(args []string) {
	fs := newFlagSet("scan")
	urls := fs.String("urls", "", "urls file (required)")
	conc := fs.Int("concurrency", 8, "parallel workers")
	rps := fs.Float64("rps", 30, "rate limit")
	tags := fs.String("tags", scanTags, "comma-separated template tags")
	all := fs.Bool("all-templates", false, "use ALL templates (multi-hour); default is tag-filtered")
	fs.Parse(args)
	if *urls == "" {
		fail("--urls is required")
	}
	old := scanTags
	scanTags = *tags
	cmdScan(*urls, *conc, "-", *rps, *all)
	scanTags = old
}

func cmdFullDispatch(args []string) {
	fs := newFlagSet("full")
	domain := fs.String("domain", "", "domain to recon (required)")
	dir := fs.String("dir", "", "output directory (default cwd)")
	conc := fs.Int("concurrency", 8, "parallel workers")
	fs.Parse(args)
	if *domain == "" {
		fail("--domain is required")
	}
	cmdFull(*domain, *dir, *conc)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func runCmd(args []string) {
	o, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loom-exec: %v\n", err)
		os.Exit(2)
	}

	var hosts []string
	if o.hostsPath == "-" {
		hosts, err = readLines(os.Stdin)
	} else {
		var f *os.File
		f, err = os.Open(o.hostsPath)
		if err == nil {
			hosts, err = readLines(f)
			f.Close()
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "loom-exec: read hosts: %v\n", err)
		os.Exit(1)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "loom-exec: no hosts")
		os.Exit(1)
	}

	var out io.Writer = os.Stdout
	var outFile *os.File
	if o.outPath != "-" {
		outFile, err = os.Create(o.outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loom-exec: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
		out = outFile
	}
	enc := json.NewEncoder(out)

	// Split into batches.
	var batches [][]string
	for i := 0; i < len(hosts); i += o.batchSize {
		end := minInt(i+o.batchSize, len(hosts))
		batches = append(batches, hosts[i:end])
	}

	bin, err := exec.LookPath(o.tool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loom-exec: tool %q not found: %v\n", o.tool, err)
		os.Exit(1)
	}

	jobCh := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var items, errs, hostsDone, batchesDone int
	start := time.Now()
	limiter := newTokenBucket(o.rps)

	worker := func() {
		defer wg.Done()
		for bi := range jobCh {
			batch := batches[bi]
			if o.rps > 0 {
				limiter.take(len(batch))
			}
			n, e := runBatch(bin, o, batch, bi, enc, &mu)
			mu.Lock()
			items += n
			hostsDone += len(batch)
			batchesDone++
			if e != nil {
				errs++
			}
			mu.Unlock()
		}
	}

	for i := 0; i < o.concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		for i := range batches {
			jobCh <- i
		}
		close(jobCh)
	}()

	done := make(chan struct{})
	if !o.quiet {
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					mu.Lock()
					st := Stats{
						Elapsed:   time.Since(start).Round(time.Second).String(),
						DoneB:     batchesDone,
						TotalB:    len(batches),
						HostsDone: hostsDone,
						Items:     items,
						Errors:    errs,
						RPS:       float64(hostsDone) / time.Since(start).Seconds(),
					}
					mu.Unlock()
					fmt.Fprintf(os.Stderr, "[%s] batches=%d/%d hosts=%d items=%d errors=%d rps=%.1f\n",
						st.Elapsed, st.DoneB, st.TotalB, st.HostsDone, st.Items, st.Errors, st.RPS)
				case <-done:
					return
				}
			}
		}()
	}

	wg.Wait()
	close(done)

	mu.Lock()
	fmt.Fprintf(os.Stderr, "loom-exec: done %d hosts -> %d items, %d errors, %s\n",
		hostsDone, items, errs, time.Since(start).Round(time.Millisecond))
	mu.Unlock()
}

// runBatch invokes the tool once with `batch` hosts on stdin and encodes
// each stdout line as one Item. Returns item count and an error (nil on
// success).
func runBatch(bin string, o *runOptions, batch []string, bi int,
	enc *json.Encoder, mu *sync.Mutex) (int, error) {
	var cmdArgs []string
	if o.argsRaw != "" {
		cmdArgs = append(cmdArgs, strings.Fields(o.argsRaw)...)
	}
	cmd := exec.Command(bin, cmdArgs...)
	// Run the tool in its own process group so a timeout kill takes down
	// grandchildren too (e.g. `sh -c "sleep 60"` — killing just `sh`
	// leaves sleep holding the pipe open until it exits naturally).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 0, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	killGroup := func() {
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	defer killGroup()
	go func() {
		defer stdin.Close()
		for _, h := range batch {
			io.WriteString(stdin, h+"\n")
		}
	}()

	// Read all stdout (bounded by timeout).
	linesCh := make(chan []string, 1)
	errCh := make(chan error, 1)
	go func() {
		data, e := io.ReadAll(stdout)
		if e != nil {
			errCh <- e
			return
		}
		linesCh <- splitLines(string(data))
	}()

	select {
	case <-time.After(o.timeout):
		killGroup()
		<-stdoutClosed(stdout)
		return 0, fmt.Errorf("batch %d: timeout after %s", bi, o.timeout)
	case e := <-errCh:
		cmd.Wait()
		return 0, e
	case lines := <-linesCh:
		cmd.Wait()
		mu.Lock()
		for _, ln := range lines {
			if ln == "" {
				continue
			}
			enc.Encode(Item{
				TS:    float64(time.Now().UnixNano()) / 1e9,
				Tool:  o.tool,
				Batch: bi,
				Hosts: len(batch),
				Value: ln,
			})
		}
		mu.Unlock()
		return len(lines), nil
	}
}

// stdoutClosed drains and closes a stdout pipe (used after kill).
func stdoutClosed(stdout io.ReadCloser) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, stdout)
		stdout.Close()
		close(done)
	}()
	return done
}

// readLines reads newline-separated lines, trimming whitespace, skipping blanks.
func readLines(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return splitLines(string(data)), nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := strings.TrimSpace(s[start:i])
			if line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := strings.TrimSpace(s[start:])
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
