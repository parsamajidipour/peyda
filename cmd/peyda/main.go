package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/deps"
	"github.com/parsamajidipour/peyda/internal/reconrun"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "run":
		err = runCommand(os.Args[2:])
	case "deps":
		err = depsCommand(os.Args[2:])
	case "init":
		err = initCommand(os.Args[2:])
	case "config":
		err = configCommand(os.Args[2:])
	case "version":
		fmt.Printf("peyda %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		if strings.HasPrefix(os.Args[1], "-") {
			err = fmt.Errorf("unknown command: %s", os.Args[1])
		} else {
			err = runCommand(os.Args[1:])
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`peyda - scope-first reconnaissance CLI

Runs the default reconnaissance pipeline and writes a normalized dataset to
results/<target>/.

Usage:
  peyda example.com [-silent] [-json|-jsonl] [-o result.txt]
  peyda run example.com [--config peyda.json] [--no-jsonl]
  peyda deps [--check | --update]
  peyda init example.com [-d YYYY-MM-DD] [-o runs] [-e excluded.txt]
  peyda config init [-o peyda.example.json]
  peyda version

Commands:
  run      Prepare dependencies and run the complete recon pipeline
  deps     Check, install, or update recon dependencies
  init     Create a scoped run folder
  config   Write an example JSON config
  version  Print the CLI version

Examples:
  peyda example.com
  peyda deps --check
  peyda deps
  peyda example.com -silent
  peyda example.com -jsonl -o results.jsonl
  peyda example.com --crawl-duration 2m --max-js-downloads 500
  peyda run example.com -p 25
  peyda run example.com --no-jsonl
  peyda config init -o peyda.json
  peyda run --config peyda.json

Output:
  dataset: ./results/example.com/
  internal: ./runs/example.com/YYYY-MM-DD/
  with --output-dir: <base>/results/example.com/ and <base>/runs/example.com/YYYY-MM-DD/

`)
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	target := fs.String("t", "", "target root domain; optional when target is passed positionally")
	date := fs.String("d", "", "UTC run date")
	outputFile := fs.String("o", "", "write CLI output to file")
	outputRoot := fs.String("output-dir", "", "base output root; defaults to the current directory")
	configPath := fs.String("config", "", "optional JSON config file")
	excluded := fs.String("e", "", "excluded-host file")
	probeRate := fs.Int("p", 0, "HTTP probe rate limit")
	crawlDepth := fs.Int("crawl-depth", 0, "maximum crawler depth")
	crawlDuration := fs.String("crawl-duration", "", "maximum crawler duration, e.g. 45s or 5m")
	maxDomainPages := fs.Int("max-domain-pages", 0, "maximum crawled pages per domain")
	maxJSDownloads := fs.Int("max-js-downloads", 0, "maximum JavaScript files to download for local endpoint extraction")
	skipDeps := fs.Bool("skip-deps", false, "skip dependency preparation")
	noJSONL := fs.Bool("no-jsonl", false, "disable normalized/recon-events.jsonl")
	silent := fs.Bool("silent", false, "print only the final dataset directory")
	jsonOut := fs.Bool("json", false, "print final output as JSON")
	jsonlOut := fs.Bool("jsonl", false, "print final output as JSONL")
	positionalTarget, filteredArgs, err := extractRunTarget(args)
	if err != nil {
		return err
	}
	if err := fs.Parse(filteredArgs); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *target != "" {
		cfg.Target = *target
	}
	if cfg.Target == "" && positionalTarget != "" {
		cfg.Target = positionalTarget
	}
	if *date != "" {
		cfg.RunDate = *date
	}
	if *outputRoot != "" {
		cfg.OutputRoot = filepath.Join(*outputRoot, "runs")
		cfg.ResultsRoot = filepath.Join(*outputRoot, "results")
	}
	if *outputFile != "" {
		cfg.OutputFile = *outputFile
	}
	if *excluded != "" {
		cfg.ExcludedFile = *excluded
	}
	if *probeRate > 0 {
		cfg.ProbeRate = *probeRate
	}
	if *crawlDepth > 0 {
		cfg.CrawlDepth = *crawlDepth
	}
	if *crawlDuration != "" {
		cfg.CrawlDuration = *crawlDuration
	}
	if *maxDomainPages > 0 {
		cfg.MaxDomainPages = *maxDomainPages
	}
	if *maxJSDownloads > 0 {
		cfg.MaxJSDownloads = *maxJSDownloads
	}
	if *skipDeps {
		cfg.SkipDeps = true
	}
	if *noJSONL {
		cfg.WriteJSONL = false
	}
	if *silent {
		cfg.Silent = true
	}
	switch {
	case *jsonOut && *jsonlOut:
		return errors.New("use only one output format: -json or -jsonl")
	case *jsonOut:
		cfg.OutputFormat = "json"
	case *jsonlOut:
		cfg.OutputFormat = "jsonl"
		cfg.WriteJSONL = true
	default:
		cfg.OutputFormat = "human"
	}

	if cfg.Target == "" {
		return errors.New("target is required")
	}
	if err := cfg.ApplyDefaults(); err != nil {
		return err
	}

	root, _ := reconrun.FindRepoRoot()
	if cfg.OutputFormat == "human" && !cfg.Silent {
		printBanner()
	}
	return reconrun.Run(root, cfg)
}

func extractRunTarget(args []string) (string, []string, error) {
	valueFlags := map[string]struct{}{
		"-t": {}, "--t": {},
		"-d": {}, "--d": {},
		"-o": {}, "--o": {},
		"-e": {}, "--e": {},
		"-p": {}, "--p": {},
		"--config":           {},
		"--output-dir":       {},
		"--crawl-depth":      {},
		"--crawl-duration":   {},
		"--max-domain-pages": {},
		"--max-js-downloads": {},
	}

	var target string
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if target == "" && i+1 < len(args) {
				target = args[i+1]
				i++
				continue
			}
			filtered = append(filtered, arg)
			continue
		}
		if strings.HasPrefix(arg, "-") {
			filtered = append(filtered, arg)
			if _, needsValue := valueFlags[arg]; needsValue && i+1 < len(args) {
				i++
				filtered = append(filtered, args[i])
			}
			continue
		}
		if target == "" {
			target = arg
			continue
		}
		return "", nil, fmt.Errorf("unexpected extra argument: %s", arg)
	}
	return target, filtered, nil
}

func printBanner() {
	fmt.Print(`
 ____  _______   ______   _
|  _ \| ____\ \ / /  _ \ / \
| |_) |  _|  \ V /| | | / _ \
|  __/| |___  | | | |_| / ___ \
|_|   |_____| |_| |____/_/   \_\

        scope-first recon automation
        authorized targets only

[INF] Scope-first recon workflow initialized
[INF] Active probing is bounded by built-in safety limits and config

`)
}

func depsCommand(args []string) error {
	fs := flag.NewFlagSet("deps", flag.ContinueOnError)
	check := fs.Bool("check", false, "check only")
	update := fs.Bool("update", false, "force update")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, _ := reconrun.FindRepoRoot()

	mode := deps.Ensure
	if *check {
		mode = deps.Check
	}
	if *update {
		mode = deps.Update
	}
	return deps.Run(root, mode, os.Stdout)
}

func initCommand(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	target := fs.String("t", "", "target root domain; optional when target is passed positionally")
	date := fs.String("d", time.Now().UTC().Format("2006-01-02"), "UTC run date")
	outputRoot := fs.String("o", "runs", "output root; defaults to ./runs in the current directory")
	excluded := fs.String("e", "", "excluded-host file")
	positionalTarget, filteredArgs, err := extractRunTarget(args)
	if err != nil {
		return err
	}
	if err := fs.Parse(filteredArgs); err != nil {
		return err
	}
	finalTarget := *target
	if finalTarget == "" {
		finalTarget = positionalTarget
	}
	if finalTarget == "" {
		return errors.New("target is required")
	}

	cfg := config.Config{
		Target:       finalTarget,
		RunDate:      *date,
		OutputRoot:   *outputRoot,
		ExcludedFile: *excluded,
	}
	runDir, err := reconrun.Init(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("Created recon run:\n  %s\n", runDir)
	return nil
}

func configCommand(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("usage: peyda config init [-o peyda.example.json]")
	}

	fs := flag.NewFlagSet("config init", flag.ContinueOnError)
	output := fs.String("o", "peyda.example.json", "output config path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if err := config.Write(*output, config.Example()); err != nil {
		return err
	}
	fmt.Printf("Config written: %s\n", *output)
	return nil
}
