package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"enumscan/internal/api"
	"enumscan/internal/config"
	"enumscan/internal/engine"
	"enumscan/internal/inventory"
	"enumscan/internal/models"
	"enumscan/internal/modules"
	"enumscan/internal/reporting"
	"enumscan/internal/store"
	"enumscan/internal/tui"
	"enumscan/internal/vulnerability"
)

func main() {
	cfgPath := flag.String("config", "configs/example.yaml", "path to YAML config")
	flag.Parse()

	subcmd := "server"
	if flag.NArg() >= 1 {
		subcmd = flag.Arg(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	// Doctor intentionally runs before opening the datastore. Its default mode
	// is a local configuration preflight; -remote is an explicit bounded
	// operator action. Neither mode creates data or exposes credential values.
	if subcmd == "doctor" {
		doctorFlags := flag.NewFlagSet("doctor", flag.ExitOnError)
		format := doctorFlags.String("format", "text", "text or json")
		remote := doctorFlags.Bool("remote", false, "explicitly contact configured credentialed providers for bounded diagnostics")
		_ = doctorFlags.Parse(flag.Args()[1:])
		report := modules.DiagnosePassiveIntel(cfg.PassiveIntel, os.LookupEnv)
		if *remote {
			report = modules.DiagnosePassiveIntelRemote(context.Background(), cfg.PassiveIntel, os.LookupEnv)
		}
		switch strings.ToLower(strings.TrimSpace(*format)) {
		case "text":
			fmt.Print(modules.FormatPassiveIntelDoctorText(report))
		case "json":
			encoded, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				log.Fatalf("encode doctor report: %v", err)
			}
			fmt.Println(string(encoded))
		default:
			log.Fatalf("unsupported doctor format %q (use text or json)", *format)
		}
		return
	}
	if strings.HasPrefix(subcmd, "plugin-") {
		if err := runPluginCommand(subcmd, flag.Args()[1:]); err != nil {
			log.Fatalf("%s: %v", subcmd, err)
		}
		return
	}
	// PostgreSQL is an explicit operational-preflight target while the scanner
	// continues its staged migration to the datastore interface. Keeping this
	// command separate prevents a configuration typo from silently placing scan
	// evidence in a different backend.
	if subcmd == "postgres-migrate" {
		if cfg.Database.Driver != "postgres" {
			log.Fatal("postgres-migrate requires database.driver: postgres")
		}
		dsn := os.Getenv(cfg.Database.PostgresDSNEnv)
		if strings.TrimSpace(dsn) == "" {
			log.Fatalf("postgres-migrate requires a non-empty %s environment variable", cfg.Database.PostgresDSNEnv)
		}
		pg := store.NewPostgresStore(dsn)
		if err := pg.ConfigurePool(cfg.Database.PostgresMaxOpenConns, cfg.Database.PostgresMaxIdleConns); err != nil {
			log.Fatalf("configure PostgreSQL pool: %v", err)
		}
		defer func() { _ = pg.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := pg.OpenContext(ctx); err != nil {
			log.Fatalf("open PostgreSQL: %v", err)
		}
		if err := pg.Migrate(ctx); err != nil {
			log.Fatalf("migrate PostgreSQL: %v", err)
		}
		fmt.Println("PostgreSQL core schema migrated successfully.")
		return
	}

	var db *store.SQLiteCLI
	var secretManager store.SecretsManager
	if cfg.Secrets.Provider != "" {
		secretManager, err = configuredSecretsManager(cfg)
		if err != nil {
			log.Fatalf("configure secret manager: %v", err)
		}
	}
	keyMaterial := ""
	keySource := ""
	if cfg.Database.EncryptionKeySecret != "" {
		keyMaterial, err = secretManager.GetSecret(context.Background(), cfg.Database.EncryptionKeySecret)
		keySource = "configured secret manager key " + cfg.Database.EncryptionKeySecret
	} else if cfg.Database.EncryptionKeyEnv != "" {
		keyMaterial = os.Getenv(cfg.Database.EncryptionKeyEnv)
		keySource = cfg.Database.EncryptionKeyEnv
	}
	if keySource != "" {
		if err != nil {
			log.Fatalf("read live datastore encryption key from %s: %v", keySource, err)
		}
		key, keyErr := store.DecodeBackupKey(keyMaterial)
		if keyErr != nil {
			log.Fatalf("read live datastore encryption key from %s: %v", keySource, keyErr)
		}
		db, err = store.OpenEncryptedSQLiteCLI(cfg.Database.Path, key)
		for index := range key {
			key[index] = 0
		}
	} else {
		db, err = store.OpenSQLiteCLI(cfg.Database.Path)
	}
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	switch subcmd {
	case "init-db":
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		fmt.Printf("Initialized database at %s\n", cfg.Database.Path)
	case "backup-encrypted":
		if flag.NArg() < 2 {
			log.Fatal("backup-encrypted requires an output path")
		}
		backupFlags := flag.NewFlagSet("backup-encrypted", flag.ExitOnError)
		keyEnv := backupFlags.String("key-env", "ENUMSCAN_BACKUP_KEY", "environment variable holding a base64 AES-256 backup key")
		_ = backupFlags.Parse(flag.Args()[2:])
		key, err := store.DecodeBackupKey(os.Getenv(*keyEnv))
		if err != nil {
			log.Fatalf("read encrypted backup key from %s: %v", *keyEnv, err)
		}
		if err := db.BackupEncrypted(ctx, flag.Arg(1), key); err != nil {
			log.Fatalf("create encrypted backup: %v", err)
		}
		fmt.Printf("Wrote AES-256-GCM authenticated encrypted backup to %s. The key was read only from %s.\n", flag.Arg(1), *keyEnv)
	case "restore-encrypted":
		if flag.NArg() < 2 {
			log.Fatal("restore-encrypted requires an encrypted backup path")
		}
		restoreFlags := flag.NewFlagSet("restore-encrypted", flag.ExitOnError)
		keyEnv := restoreFlags.String("key-env", "ENUMSCAN_BACKUP_KEY", "environment variable holding a base64 AES-256 backup key")
		confirm := restoreFlags.Bool("confirm", false, "required acknowledgement that restore overwrites the configured SQLite database")
		_ = restoreFlags.Parse(flag.Args()[2:])
		if !*confirm {
			log.Fatal("restore-encrypted is destructive; repeat with -confirm after verifying the backup path and configured database")
		}
		key, err := store.DecodeBackupKey(os.Getenv(*keyEnv))
		if err != nil {
			log.Fatalf("read encrypted backup key from %s: %v", *keyEnv, err)
		}
		if err := db.RestoreEncrypted(ctx, flag.Arg(1), key); err != nil {
			log.Fatalf("restore encrypted backup: %v", err)
		}
		fmt.Printf("Restored authenticated encrypted backup from %s into %s.\n", flag.Arg(1), cfg.Database.Path)
	case "secret-check", "secret-set", "secret-rotate":
		if secretManager == nil {
			log.Fatal("secret operation requires a configured secrets.provider")
		}
		if flag.NArg() < 2 {
			log.Fatalf("%s requires a secret name", subcmd)
		}
		secretName := flag.Arg(1)
		switch subcmd {
		case "secret-check":
			if _, err := secretManager.GetSecret(ctx, secretName); err != nil {
				log.Fatalf("secret is unavailable: %v", err)
			}
			fmt.Printf("Secret %s is available from %s; its value was not displayed.\n", secretName, cfg.Secrets.Provider)
		case "secret-set", "secret-rotate":
			operationFlags := flag.NewFlagSet(subcmd, flag.ExitOnError)
			valueEnv := operationFlags.String("value-env", "ENUMSCAN_SECRET_VALUE", "environment variable containing the new secret value")
			_ = operationFlags.Parse(flag.Args()[2:])
			value := os.Getenv(*valueEnv)
			if value == "" {
				log.Fatalf("%s is empty", *valueEnv)
			}
			if subcmd == "secret-set" {
				err = secretManager.SetSecret(ctx, secretName, value)
			} else {
				err = secretManager.RotateSecret(ctx, secretName, value)
			}
			if err != nil {
				log.Fatalf("%s failed: %v", subcmd, err)
			}
			fmt.Printf("Secret %s was updated through %s; its value was not displayed.\n", secretName, cfg.Secrets.Provider)
		}
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
	case "monitor":
		if !cfg.Monitoring.Enabled {
			log.Fatal("monitoring is disabled; set monitoring.enabled: true in an explicitly authorized configuration")
		}
		monitorFlags := flag.NewFlagSet("monitor", flag.ExitOnError)
		prefix := monitorFlags.String("prefix", "monitor", "scan ID prefix")
		_ = monitorFlags.Parse(flag.Args()[1:])
		if err := runBoundedMonitoring(ctx, cfg, db, *prefix); err != nil {
			log.Fatalf("monitor scans: %v", err)
		}
	case "git-secrets":
		if flag.NArg() < 2 {
			log.Fatal("git-secrets requires a scan id")
		}
		gitFlags := flag.NewFlagSet("git-secrets", flag.ExitOnError)
		repository := gitFlags.String("repo", "", "explicit local Git worktree to inspect")
		maxCommits := gitFlags.Int("max-commits", 250, "maximum commits to inspect (1-2000)")
		_ = gitFlags.Parse(flag.Args()[2:])
		if *repository == "" {
			log.Fatal("git-secrets requires -repo <explicit-local-worktree>")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		scanID := flag.Arg(1)
		if err := db.StartScan(ctx, scanID); err != nil {
			log.Fatalf("start Git-history scan: %v", err)
		}
		findings, err := modules.ScanGitHistory(ctx, *repository, *maxCommits)
		if err != nil {
			_ = db.FinishScan(ctx, scanID, "failed", err.Error())
			log.Fatalf("scan Git history: %v", err)
		}
		for _, finding := range findings {
			match := finding.Match
			metadata := fmt.Sprintf("source=local_git_history;commit=%s;kind=%s;validated=%t;fingerprint=%s", finding.Commit, match.Kind, match.Validated, match.Redacted)
			_ = db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "secret_exposure", Value: match.Kind + ":" + match.Redacted, Parent: "local_git_repository", Metadata: metadata})
			_ = db.AddFinding(ctx, models.Finding{ScanID: scanID, Severity: match.Risk, Confidence: match.Confidence, Verification: "heuristic", Asset: "local_git_repository", Title: "Potential " + strings.ReplaceAll(match.Kind, "_", " ") + " in local Git history", Evidence: "Commit " + finding.Commit + "; redacted fingerprint " + match.Redacted + "; local format validation=" + fmt.Sprint(match.Validated), Remediation: "Remove the secret from active files, rotate it, and follow your approved history-rewrite policy."})
		}
		if err := db.FinishScan(ctx, scanID, "completed", ""); err != nil {
			log.Fatalf("finish Git-history scan: %v", err)
		}
		fmt.Printf("Git-history scan %s completed: %d redacted potential-secret findings recorded\n", scanID, len(findings))
	case "report":
		if flag.NArg() < 2 {
			log.Fatal("report requires a scan id")
		}
		reportFlags := flag.NewFlagSet("report", flag.ExitOnError)
		format := reportFlags.String("format", "json", "json, markdown, executive, technical, triage, sarif, or neo4j")
		_ = reportFlags.Parse(flag.Args()[2:])
		path, err := reporting.Write(ctx, db, flag.Arg(1), *format, cfg.Reporting.OutputDir)
		if err != nil {
			log.Fatalf("write report: %v", err)
		}
		fmt.Printf("Wrote %s report to %s\n", *format, path)
	case "notify-webhook":
		if flag.NArg() < 2 {
			log.Fatal("notify-webhook requires a scan id")
		}
		webhookFlags := flag.NewFlagSet("notify-webhook", flag.ExitOnError)
		endpoint := webhookFlags.String("url", "", "explicit HTTPS webhook endpoint (HTTP allowed for localhost testing)")
		_ = webhookFlags.Parse(flag.Args()[2:])
		if *endpoint == "" {
			log.Fatal("notify-webhook requires -url <explicit-webhook-endpoint>")
		}
		if err := reporting.DeliverWebhook(ctx, db, flag.Arg(1), *endpoint); err != nil {
			log.Fatalf("deliver webhook: %v", err)
		}
		fmt.Printf("Delivered evidence-only summary for scan %s to the explicit webhook endpoint\n", flag.Arg(1))
	case "notify-slack":
		if flag.NArg() < 2 {
			log.Fatal("notify-slack requires a scan id")
		}
		slackFlags := flag.NewFlagSet("notify-slack", flag.ExitOnError)
		endpoint := slackFlags.String("url", "", "explicit Slack incoming-webhook URL")
		_ = slackFlags.Parse(flag.Args()[2:])
		if *endpoint == "" {
			log.Fatal("notify-slack requires -url <explicit-slack-webhook-url>")
		}
		if err := reporting.DeliverSlackWebhook(ctx, db, flag.Arg(1), *endpoint); err != nil {
			log.Fatalf("deliver Slack webhook: %v", err)
		}
		fmt.Printf("Delivered compact evidence summary for scan %s to the explicit Slack webhook\n", flag.Arg(1))
	case "notify-email":
		if flag.NArg() < 2 {
			log.Fatal("notify-email requires a scan id")
		}
		emailFlags := flag.NewFlagSet("notify-email", flag.ExitOnError)
		server := emailFlags.String("server", "", "explicit SMTP host:port")
		from := emailFlags.String("from", "", "sender email address")
		to := emailFlags.String("to", "", "recipient email address")
		username := emailFlags.String("username", "", "SMTP username (password is read from ENUMSCAN_SMTP_PASSWORD)")
		_ = emailFlags.Parse(flag.Args()[2:])
		password := os.Getenv("ENUMSCAN_SMTP_PASSWORD")
		if *server == "" || *from == "" || *to == "" {
			log.Fatal("notify-email requires -server, -from, and -to")
		}
		if err := reporting.DeliverEmail(ctx, db, flag.Arg(1), *server, *from, *to, *username, password); err != nil {
			log.Fatalf("deliver email: %v", err)
		}
		fmt.Printf("Delivered compact evidence summary for scan %s to the explicit SMTP recipient\n", flag.Arg(1))
	case "local-llm-summary":
		if flag.NArg() < 2 {
			log.Fatal("local-llm-summary requires a scan id")
		}
		path, err := reporting.WriteLocalLLMAdvisory(ctx, db, flag.Arg(1), cfg.Reporting)
		if err != nil {
			log.Fatalf("write local LLM advisory: %v", err)
		}
		fmt.Printf("Wrote local LLM advisory to %s\n", path)
	case "sync-neo4j":
		if flag.NArg() < 2 {
			log.Fatal("sync-neo4j requires a scan id")
		}
		if cfg.Neo4j.URI == "" {
			log.Fatal("sync-neo4j requires neo4j.uri, neo4j.username, and neo4j.password_env in config")
		}
		password := os.Getenv(cfg.Neo4j.PasswordEnv)
		if password == "" {
			log.Fatalf("sync-neo4j requires the %s environment variable", cfg.Neo4j.PasswordEnv)
		}
		count, err := store.SyncScanToNeo4j(ctx, db, store.NewNeo4jStore(cfg.Neo4j.URI, cfg.Neo4j.Username, password), flag.Arg(1))
		if err != nil {
			log.Fatalf("sync Neo4j: %v", err)
		}
		fmt.Printf("Synchronized %d persisted evidence records for scan %s to Neo4j\n", count, flag.Arg(1))
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
		version := importFlags.String("version", "", "feed version or release timestamp")
		provenance := importFlags.String("provenance", "operator-provided NVD feed", "feed source/provenance")
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
		count, err := importer.ImportJSONWithMetadata(ctx, f, store.FeedMetadata{Source: "nvd", Version: *version, Provenance: *provenance, FetchedAt: time.Now().UTC()})
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
	case "score-risk":
		if flag.NArg() < 2 {
			log.Fatal("score-risk requires a scan id")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		assessments, err := vulnerability.NewRiskEngine(db).AnalyzeScan(ctx, flag.Arg(1))
		if err != nil {
			log.Fatalf("score risk: %v", err)
		}
		fmt.Printf("Recorded %d risk assessments for scan %s\n", len(assessments), flag.Arg(1))
	case "compare-scans":
		if flag.NArg() < 3 {
			log.Fatal("compare-scans requires baseline and current scan ids")
		}
		result, err := inventory.CompareStoredScans(ctx, db, flag.Arg(1), flag.Arg(2))
		if err != nil {
			log.Fatalf("compare scans: %v", err)
		}
		path, err := inventory.WriteChangeReport(cfg.Reporting.OutputDir, flag.Arg(1), flag.Arg(2), result)
		if err != nil {
			log.Fatalf("write change report: %v", err)
		}
		fmt.Printf("Wrote scan change report to %s\n", path)
	case "distributed-status":
		distributedFlags := flag.NewFlagSet("distributed-status", flag.ExitOnError)
		format := distributedFlags.String("format", "text", "text or json")
		limit := distributedFlags.Int("limit", 50, "maximum jobs and agents to display (1-200)")
		_ = distributedFlags.Parse(flag.Args()[1:])
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		status, err := db.DistributedCoordinatorStatus(ctx, *limit)
		if err != nil {
			log.Fatalf("read distributed coordinator status: %v", err)
		}
		if err := printDistributedStatus(status, *format); err != nil {
			log.Fatal(err)
		}
	case "distributed-enqueue":
		if flag.NArg() < 2 {
			log.Fatal("distributed-enqueue requires a scan id")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		configBytes, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatalf("read configuration for coordinator digest: %v", err)
		}
		digest := sha256.Sum256(configBytes)
		job, err := db.EnqueueDistributedScanJob(ctx, flag.Arg(1), cfg.Scope.Authorization, fmt.Sprintf("%x", digest))
		if err != nil {
			log.Fatalf("enqueue distributed scan job: %v", err)
		}
		fmt.Printf("Queued coordinator job %s for scan %s. This does not start a remote scan; a future mutually authenticated agent transport must obtain the authorized configuration.\n", job.ID, job.ScanID)
	case "distributed-enroll":
		distributedFlags := flag.NewFlagSet("distributed-enroll", flag.ExitOnError)
		agentID := distributedFlags.String("agent", "", "agent identifier")
		publicKey := distributedFlags.String("public-key", "", "unpadded base64 Ed25519 public key")
		_ = distributedFlags.Parse(flag.Args()[1:])
		if *agentID == "" || *publicKey == "" {
			log.Fatal("distributed-enroll requires -agent and -public-key")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		agent, err := db.RegisterDistributedAgent(ctx, *agentID, *publicKey)
		if err != nil {
			log.Fatalf("enroll distributed agent: %v", err)
		}
		fmt.Printf("Enrolled agent %s with public-key fingerprint %s. Enrollment alone cannot accept remote work.\n", agent.ID, agent.PublicKeyFingerprint)
	case "distributed-heartbeat":
		distributedFlags := flag.NewFlagSet("distributed-heartbeat", flag.ExitOnError)
		agentID := distributedFlags.String("agent", "", "enrolled agent identifier")
		_ = distributedFlags.Parse(flag.Args()[1:])
		if *agentID == "" {
			log.Fatal("distributed-heartbeat requires -agent")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		if err := db.HeartbeatDistributedAgent(ctx, *agentID); err != nil {
			log.Fatalf("record agent heartbeat: %v", err)
		}
		fmt.Printf("Recorded local coordinator heartbeat for agent %s.\n", *agentID)
	case "distributed-lease":
		distributedFlags := flag.NewFlagSet("distributed-lease", flag.ExitOnError)
		agentID := distributedFlags.String("agent", "", "online enrolled agent identifier")
		leaseSeconds := distributedFlags.Int("lease-seconds", 60, "lease duration (1-1800 seconds)")
		_ = distributedFlags.Parse(flag.Args()[1:])
		if *agentID == "" {
			log.Fatal("distributed-lease requires -agent")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		job, err := db.LeaseDistributedScanJob(ctx, *agentID, time.Duration(*leaseSeconds)*time.Second)
		if err != nil {
			log.Fatalf("lease distributed scan job: %v", err)
		}
		encoded, _ := json.MarshalIndent(job, "", "  ")
		fmt.Println(string(encoded))
	case "distributed-complete":
		distributedFlags := flag.NewFlagSet("distributed-complete", flag.ExitOnError)
		agentID := distributedFlags.String("agent", "", "lease-owning agent identifier")
		jobID := distributedFlags.String("job", "", "leased job identifier")
		status := distributedFlags.String("status", "completed", "completed or failed")
		_ = distributedFlags.Parse(flag.Args()[1:])
		if *agentID == "" || *jobID == "" {
			log.Fatal("distributed-complete requires -agent and -job")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		if err := db.CompleteDistributedScanJob(ctx, *jobID, *agentID, *status); err != nil {
			log.Fatalf("complete distributed scan job: %v", err)
		}
		fmt.Printf("Recorded %s for coordinator job %s.\n", *status, *jobID)
	case "distributed-agent":
		agentFlags := flag.NewFlagSet("distributed-agent", flag.ExitOnError)
		agentID := agentFlags.String("agent", "", "enrolled agent identifier")
		coordinatorURL := agentFlags.String("coordinator", "", "HTTPS coordinator base URL")
		privateKeyEnv := agentFlags.String("private-key-env", "ENUMSCAN_AGENT_PRIVATE_KEY", "environment variable containing the unpadded base64 Ed25519 private key")
		leaseSeconds := agentFlags.Int("lease-seconds", 300, "lease duration (1-1800 seconds)")
		_ = agentFlags.Parse(flag.Args()[1:])
		if *agentID == "" || *coordinatorURL == "" || *leaseSeconds < 1 || *leaseSeconds > 1800 {
			log.Fatal("distributed-agent requires -agent, -coordinator, and a lease duration from 1 to 1800 seconds")
		}
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate agent evidence store: %v", err)
		}
		client, err := engine.NewDistributedAgentClient(*agentID, *coordinatorURL, os.Getenv(*privateKeyEnv), nil)
		if err != nil {
			log.Fatalf("configure distributed agent: %v", err)
		}
		if err := client.Heartbeat(ctx); err != nil {
			log.Fatalf("authenticate agent heartbeat: %v", err)
		}
		job, err := client.Lease(ctx, time.Duration(*leaseSeconds)*time.Second)
		if errors.Is(err, engine.ErrNoRemoteJob) {
			fmt.Println("No distributed scan job is currently available.")
			return
		}
		if err != nil {
			log.Fatalf("lease distributed scan: %v", err)
		}
		configBytes, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatalf("read agent configuration: %v", err)
		}
		digest := sha256.Sum256(configBytes)
		if fmt.Sprintf("%x", digest) != job.ConfigDigest || cfg.Scope.Authorization != job.AuthorizationRef {
			_ = client.Complete(ctx, job.ID, "failed")
			log.Fatal("leased job does not match this agent's configuration digest and authorization reference")
		}
		runner := engine.New(cfg, db)
		if err := runner.Run(ctx, job.ScanID); err != nil {
			_ = client.Complete(ctx, job.ID, "failed")
			log.Fatalf("distributed scan failed: %v", err)
		}
		assets, err := db.Assets(ctx, job.ScanID)
		if err != nil {
			log.Fatalf("read distributed assets: %v", err)
		}
		findings, err := db.Findings(ctx, job.ScanID)
		if err != nil {
			log.Fatalf("read distributed findings: %v", err)
		}
		events, err := db.Events(ctx, job.ScanID)
		if err != nil {
			log.Fatalf("read distributed events: %v", err)
		}
		if err := client.SubmitEvidence(ctx, models.DistributedEvidence{JobID: job.ID, Assets: assets, Findings: findings, Events: events}); err != nil {
			log.Fatalf("submit distributed evidence: %v", err)
		}
		if err := client.Complete(ctx, job.ID, "completed"); err != nil {
			log.Fatalf("complete distributed scan: %v", err)
		}
		fmt.Printf("Distributed scan %s completed and its evidence was accepted by the coordinator.\n", job.ScanID)
	case "tui":
		if err := db.Migrate(ctx); err != nil {
			log.Fatalf("migrate db: %v", err)
		}
		if err := tui.Run(db); err != nil {
			log.Fatalf("terminal dashboard: %v", err)
		}
	case "server", "serve", "start", "dashboard":
		serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
		port := serverFlags.Int("port", 8080, "API server port")
		listenAddress := serverFlags.String("listen", "127.0.0.1", "listen address; non-loopback requires TLS")
		tlsCert := serverFlags.String("tls-cert", "", "TLS certificate path")
		tlsKey := serverFlags.String("tls-key", "", "TLS private key path")
		if flag.NArg() > 1 {
			_ = serverFlags.Parse(flag.Args()[1:])
		}
		srv := api.NewServer(db, *port)
		srv.SetConfig(cfg)
		srv.SetListenAddress(*listenAddress)
		srv.SetTLS(*tlsCert, *tlsKey)
		if cfg.API.RequireAuth {
			tokens, err := parseAPITokens(os.Getenv(cfg.API.TokensEnv))
			if err != nil {
				log.Fatalf("configure API authentication: %v", err)
			}
			srv.SetAPITokens(tokens)
			srv.SetAPITokenLoader(func() (map[string]string, error) {
				return parseAPITokens(os.Getenv(cfg.API.TokensEnv))
			})
		}
		fmt.Printf("Starting enumscan API server (REST, WebSocket, GraphQL) on port %d...\n", *port)
		if err := srv.ListenAndServe(ctx); err != nil {
			log.Fatalf("API server error: %v", err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func configuredSecretsManager(cfg models.Config) (store.SecretsManager, error) {
	return store.NewConfiguredSecretsManager(store.SecretsManagerConfig{
		Provider: store.ProviderType(cfg.Secrets.Provider), Endpoint: cfg.Secrets.Endpoint,
		TokenEnv: cfg.Secrets.TokenEnv, TokenFile: cfg.Secrets.TokenFile, Namespace: cfg.Secrets.Namespace,
		Project: cfg.Secrets.Project, Region: cfg.Secrets.Region,
		Mount: cfg.Secrets.Mount, Service: cfg.Secrets.Service,
	})
}

func parseAPITokens(value string) (map[string]string, error) {
	tokens := make(map[string]string)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		token, role, ok := strings.Cut(item, ":")
		role = strings.ToLower(strings.TrimSpace(role))
		if !ok || strings.TrimSpace(token) == "" || (role != "viewer" && role != "analyst" && role != "admin") {
			return nil, fmt.Errorf("%s must contain comma-separated token:viewer|analyst|admin entries", "api token environment variable")
		}
		tokens[strings.TrimSpace(token)] = role
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("API token environment variable is empty")
	}
	return tokens, nil
}

func printDistributedStatus(status models.DistributedCoordinatorStatus, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		encoded, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return fmt.Errorf("encode distributed coordinator status: %w", err)
		}
		fmt.Println(string(encoded))
		return nil
	case "text":
		fmt.Printf("Distributed coordinator ledger: %d jobs, %d agents\n", len(status.Jobs), len(status.Agents))
		for _, job := range status.Jobs {
			lease := ""
			if !job.LeaseUntil.IsZero() {
				lease = " lease-until=" + job.LeaseUntil.UTC().Format(time.RFC3339)
			}
			fmt.Printf("  job=%s scan=%s status=%s attempts=%d owner=%s%s\n", job.ID, job.ScanID, job.Status, job.Attempts, job.LeaseOwner, lease)
		}
		for _, agent := range status.Agents {
			fmt.Printf("  agent=%s status=%s last-heartbeat=%s fingerprint=%s\n", agent.ID, agent.Status, agent.LastHeartbeat.UTC().Format(time.RFC3339), agent.PublicKeyFingerprint)
		}
		return nil
	default:
		return fmt.Errorf("unsupported distributed-status format %q (use text or json)", format)
	}
}

func usage() {
	fmt.Println(`enumscan - authorized reconnaissance pipeline

Usage:
  enumscan [-config configs/example.yaml] init-db
	  enumscan [-config configs/example.yaml] backup-encrypted <path> [-key-env ENUMSCAN_BACKUP_KEY]
	  enumscan [-config configs/example.yaml] restore-encrypted <path> -confirm [-key-env ENUMSCAN_BACKUP_KEY]
	  enumscan [-config configs/secrets.template.yaml] secret-check <name>
	  enumscan [-config configs/secrets.template.yaml] secret-set <name> [-value-env ENUMSCAN_SECRET_VALUE]
	  enumscan [-config configs/secrets.template.yaml] secret-rotate <name> [-value-env ENUMSCAN_SECRET_VALUE]
	  enumscan [-config configs/example.yaml] run <scan-id>
	  enumscan [-config configs/example.yaml] monitor [-prefix recurring]
	  enumscan [-config configs/example.yaml] distributed-status [-format text|json] [-limit 50]
	  enumscan [-config configs/example.yaml] distributed-enqueue <scan-id>
	  enumscan [-config configs/example.yaml] distributed-enroll -agent <id> -public-key <base64-ed25519-key>
	  enumscan [-config configs/example.yaml] distributed-heartbeat -agent <id>
	  enumscan [-config configs/example.yaml] distributed-lease -agent <id> [-lease-seconds 60]
	  enumscan [-config configs/example.yaml] distributed-complete -agent <id> -job <id> [-status completed|failed]
	  enumscan [-config configs/example.yaml] distributed-agent -agent <id> -coordinator <https-url> [-private-key-env ENUMSCAN_AGENT_PRIVATE_KEY]
	  enumscan [-config configs/example.yaml] git-secrets <scan-id> -repo <explicit-local-worktree> [-max-commits 250]
	  enumscan [-config configs/example.yaml] report <scan-id> [-format json|markdown|executive|technical|triage|html|pdf|sarif|csv|neo4j]
	  enumscan [-config configs/example.yaml] notify-webhook <scan-id> -url <https-endpoint>
	  enumscan [-config configs/example.yaml] notify-slack <scan-id> -url <https-slack-webhook>
	  enumscan [-config configs/example.yaml] notify-email <scan-id> -server <host:port> -from <email> -to <email> [-username <user>]
	  enumscan [-config configs/example.yaml] local-llm-summary <scan-id>
	  enumscan [-config configs/example.yaml] sync-neo4j <scan-id>
  enumscan [-config configs/example.yaml] import-report <scan-id> -tool nuclei|openvas|nessus -file <path>
  enumscan [-config configs/example.yaml] import-nvd -file <path>
  enumscan [-config configs/example.yaml] analyze-vulnerabilities <scan-id>
  enumscan [-config configs/example.yaml] correlate <scan-id>
	  enumscan [-config configs/example.yaml] score-risk <scan-id>
	  enumscan [-config configs/example.yaml] compare-scans <baseline-scan-id> <current-scan-id>
	  enumscan [-config configs/example.yaml] doctor [-remote] [-format text|json]
	  enumscan [-config configs/postgres.yaml] postgres-migrate
	  enumscan [-config configs/example.yaml] tui
  enumscan [-config configs/example.yaml] server [-port 8080]`)
}

func runBoundedMonitoring(ctx context.Context, cfg models.Config, db *store.SQLiteCLI, prefix string) error {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "monitor"
	}
	for run := 1; run <= cfg.Monitoring.MaxRuns; run++ {
		scanID := fmt.Sprintf("%s-%s-%03d", prefix, time.Now().UTC().Format("20060102T150405Z"), run)
		started := time.Now()
		if err := engine.New(cfg, db).Run(ctx, scanID); err != nil {
			return fmt.Errorf("run %d (%s): %w", run, scanID, err)
		}
		fmt.Printf("Monitoring scan %s completed in %s (%d/%d)\n", scanID, time.Since(started).Round(time.Millisecond), run, cfg.Monitoring.MaxRuns)
		if run == cfg.Monitoring.MaxRuns {
			break
		}
		timer := time.NewTimer(time.Duration(cfg.Monitoring.IntervalMinutes) * time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
