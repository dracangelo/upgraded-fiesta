package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"enumscan/internal/config"
	"enumscan/internal/engine"
	"enumscan/internal/reporting"
	"enumscan/internal/store"
)

func main() {
	cfgPath := flag.String("config", "configs/example.yaml", "path to YAML config")
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := store.OpenSQLiteCLI(cfg.Database.Path)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	ctx := context.Background()
	switch flag.Arg(0) {
	case "init-db":
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		fmt.Printf("Initialized database at %s\n", cfg.Database.Path)
	case "run":
		if flag.NArg() < 2 {
			log.Fatal("run requires a scan id")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		runner := engine.New(cfg, db)
		start := time.Now()
		if err := runner.Run(ctx, flag.Arg(1)); err != nil {
			log.Fatalf("run scan: %v", err)
		}
		fmt.Printf("Scan %s completed in %s\n", flag.Arg(1), time.Since(start).Round(time.Millisecond))
	case "report":
		if flag.NArg() < 2 {
			log.Fatal("report requires a scan id")
		}
		reportFlags := flag.NewFlagSet("report", flag.ExitOnError)
		format := reportFlags.String("format", "json", "json or markdown")
		_ = reportFlags.Parse(flag.Args()[2:])
		path, err := reporting.Write(ctx, db, flag.Arg(1), *format, cfg.Reporting.OutputDir)
		if err != nil {
			log.Fatalf("write report: %v", err)
		}
		fmt.Printf("Wrote %s report to %s\n", *format, path)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`enumscan - authorized reconnaissance pipeline

Usage:
  enumscan [-config configs/example.yaml] init-db
  enumscan [-config configs/example.yaml] run <scan-id>
  enumscan [-config configs/example.yaml] report <scan-id> [-format json|markdown]`)
}
