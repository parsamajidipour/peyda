package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/parsamajidipour/reconx/internal/config"
	"github.com/parsamajidipour/reconx/internal/deps"
	"github.com/parsamajidipour/reconx/internal/reconrun"
)

const version = "0.2.0"

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
		fmt.Printf("reconx %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`reconx - scope-first reconnaissance CLI

Usage:
  reconx run -t example.com [--profile balanced] [--config reconx.json] [--no-jsonl]
  reconx deps [--check | --update]
  reconx init -t example.com [-d YYYY-MM-DD] [-o runs] [-e excluded.txt]
  reconx config init [-o reconx.example.json]
  reconx version

Commands:
  run      Prepare dependencies and run the complete recon pipeline
  deps     Check, install, or update recon dependencies
  init     Create a scoped run folder
  config   Write an example JSON config
  version  Print the CLI version

Profiles:
  passive   Passive collection and normalization only
  balanced  Subdomains, live probing, JS, API, cloud leads
  deep      Balanced workflow with deeper crawl/probe limits

`)
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	target := fs.String("t", "", "target root domain")
	date := fs.String("d", "", "UTC run date")
	outputRoot := fs.String("o", "", "output root")
	profile := fs.String("profile", "", "depth profile: passive, balanced, deep")
	configPath := fs.String("config", "", "optional JSON config file")
	excluded := fs.String("e", "", "excluded-host file")
	probeRate := fs.Int("p", 0, "HTTP probe rate limit")
	skipDeps := fs.Bool("skip-deps", false, "skip dependency preparation")
	noJSONL := fs.Bool("no-jsonl", false, "disable normalized/recon-events.jsonl")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *target != "" {
		cfg.Target = *target
	}
	if *date != "" {
		cfg.RunDate = *date
	}
	if *outputRoot != "" {
		cfg.OutputRoot = *outputRoot
	}
	if *profile != "" {
		cfg.Profile = *profile
	}
	if *excluded != "" {
		cfg.ExcludedFile = *excluded
	}
	if *probeRate > 0 {
		cfg.ProbeRate = *probeRate
	}
	if *skipDeps {
		cfg.SkipDeps = true
	}
	if *noJSONL {
		cfg.WriteJSONL = false
	}

	if cfg.Target == "" {
		return errors.New("target is required")
	}
	if err := cfg.ApplyProfileDefaults(); err != nil {
		return err
	}

	root, err := reconrun.FindRepoRoot()
	if err != nil {
		return err
	}
	return reconrun.Run(root, cfg)
}

func depsCommand(args []string) error {
	fs := flag.NewFlagSet("deps", flag.ContinueOnError)
	check := fs.Bool("check", false, "check only")
	update := fs.Bool("update", false, "force update")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := reconrun.FindRepoRoot()
	if err != nil {
		return err
	}

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
	target := fs.String("t", "", "target root domain")
	date := fs.String("d", time.Now().UTC().Format("2006-01-02"), "UTC run date")
	outputRoot := fs.String("o", "runs", "output root")
	excluded := fs.String("e", "", "excluded-host file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("target is required")
	}

	cfg := config.Config{
		Target:       *target,
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
		return errors.New("usage: reconx config init [-o reconx.example.json]")
	}

	fs := flag.NewFlagSet("config init", flag.ContinueOnError)
	output := fs.String("o", "reconx.example.json", "output config path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if err := config.Write(*output, config.Example()); err != nil {
		return err
	}
	fmt.Printf("Config written: %s\n", *output)
	return nil
}
