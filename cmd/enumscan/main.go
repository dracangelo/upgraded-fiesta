package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"enumscan/internal/api"
	"enumscan/internal/config"
	"enumscan/internal/engine"
	"enumscan/internal/models"
	"enumscan/internal/reporting"
	"enumscan/internal/store"
	"enumscan/internal/vulnerability"
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
		format := reportFlags.String("format", "json", "json, markdown, sarif, or neo4j")
		_ = reportFlags.Parse(flag.Args()[2:])
		path, err := reporting.Write(ctx, db, flag.Arg(1), *format, cfg.Reporting.OutputDir)
		if err != nil {
			log.Fatalf("write report: %v", err)
		}
		fmt.Printf("Wrote %s report to %s\n", *format, path)
	case "import-report":
		if flag.NArg() < 2 {
			log.Fatal("import-report requires a scan id")
		}
		importFlags := flag.NewFlagSet("import-report", flag.ExitOnError)
		tool := importFlags.String("tool", "nuclei", "nuclei, openvas, or nessus")
		file := importFlags.String("file", "", "path to report file")
		_ = importFlags.Parse(flag.Args()[2:])
		if *file == "" {
			log.Fatal("import-report requires -file <path>")
		}
		f, err := os.Open(*file)
		if err != nil {
			log.Fatalf("open report file: %v", err)
		}
		defer f.Close()
		scanID := flag.Arg(1)
		var findings []models.Finding
		switch strings.ToLower(*tool) {
		case "nuclei":
			findings, err = vulnerability.ParseNucleiJSON(f, scanID)
		case "openvas":
			findings, err = vulnerability.ParseOpenVASXML(f, scanID)
		case "nessus":
			findings, err = vulnerability.ParseNessus(f, scanID)
		default:
			log.Fatalf("unsupported tool %q", *tool)
		}
		if err != nil {
			log.Fatalf("parse report: %v", err)
		}
		for _, finding := range findings {
			_ = db.AddFinding(ctx, finding)
		}
		fmt.Printf("Imported %d findings from %s (%s) into scan %s\n", len(findings), *file, *tool, scanID)
	case "import-nvd":
		importFlags := flag.NewFlagSet("import-nvd", flag.ExitOnError)
		file := importFlags.String("file", "", "path to NVD CVE JSON feed file")
		_ = importFlags.Parse(flag.Args()[1:])
		if *file == "" {
			log.Fatal("import-nvd requires -file <path>")
		}
		f, err := os.Open(*file)
		if err != nil {
			log.Fatalf("open NVD feed file: %v", err)
		}
		defer f.Close()
		importer := vulnerability.NewNVDImporter(db)
		count, err := importer.ImportJSON(ctx, f)
		if err != nil {
			log.Fatalf("import NVD feed: %v", err)
		}
		fmt.Printf("Imported %d NVD CVE entries into database\n", count)
	case "analyze-vulnerabilities":
		if flag.NArg() < 2 {
			log.Fatal("analyze-vulnerabilities requires a scan id")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		count, err := vulnerability.NewAnalyzer(db).AnalyzeScan(ctx, flag.Arg(1))
		if err != nil {
			log.Fatalf("analyze vulnerabilities: %v", err)
		}
		fmt.Printf("Recorded %d vulnerability priority/rule results for scan %s\n", count, flag.Arg(1))
	case "correlate":
		if flag.NArg() < 2 {
			log.Fatal("correlate requires a scan id")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		result, err := vulnerability.NewCorrelationEngine(db).CorrelateEvidence(ctx, flag.Arg(1))
		if err != nil {
			log.Fatalf("correlate scan: %v", err)
		}
		fmt.Printf("Correlated %d nodes, %d edges; business impact score %d/100\n", len(result.Graph.Nodes), len(result.Graph.Edges), result.BusinessImpact)
	case "server":
		serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
		port := serverFlags.Int("port", 8080, "API server port")
		_ = serverFlags.Parse(flag.Args()[1:])
		srv := api.NewServer(db, *port)
		fmt.Printf("Starting enumscan API server (REST, WebSocket, GraphQL) on port %d...\n", *port)
		if err := srv.ListenAndServe(ctx); err != nil {
			log.Fatalf("API server error: %v", err)
		}
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
  enumscan [-config configs/example.yaml] report <scan-id> [-format json|markdown|html|pdf|sarif|neo4j]
  enumscan [-config configs/example.yaml] import-report <scan-id> -tool nuclei|openvas|nessus -file <path>
  enumscan [-config configs/example.yaml] import-nvd -file <path>
  enumscan [-config configs/example.yaml] analyze-vulnerabilities <scan-id>
  enumscan [-config configs/example.yaml] correlate <scan-id>
  enumscan [-config configs/example.yaml] server [-port 8080]`)
}
