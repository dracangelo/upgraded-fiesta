package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"enumscan/internal/config"
	"enumscan/internal/logging"
	"enumscan/internal/models"
	"enumscan/internal/modules"
	"enumscan/internal/reporting"
	"enumscan/internal/scheduler"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type Engine struct {
	cfg   models.Config
	db    *store.SQLiteCLI
	guard scope.Guard
}

func New(cfg models.Config, db *store.SQLiteCLI) Engine {
	return Engine{cfg: cfg, db: db, guard: scope.New(cfg.Scope.AllowedTargets)}
}

func (e Engine) Run(ctx context.Context, scanID string) error {
	cfg, err := config.ApplyEngineProfile(e.cfg)
	if err != nil {
		return fmt.Errorf("apply scan profile: %w", err)
	}
	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("validate scan configuration: %w", err)
	}
	if cfg.HTTP.EnableAuthenticatedCrawling {
		cookie := os.Getenv(cfg.HTTP.AuthCookieEnv)
		if strings.TrimSpace(cookie) == "" || len(cookie) > 8192 || strings.ContainsAny(cookie, "\r\n") {
			return fmt.Errorf("authenticated crawling requires a non-empty, single-line session cookie in %s", cfg.HTTP.AuthCookieEnv)
		}
	}
	guard := scope.New(cfg.Scope.AllowedTargets)
	for _, target := range cfg.Scan.Targets {
		if !guard.Allowed(target) {
			return fmt.Errorf("target %q is outside configured scope", target)
		}
	}

	if err := e.db.StartScan(ctx, scanID); err != nil {
		return err
	}
	if cfg.ActiveTesting.Enabled {
		details := fmt.Sprintf("authorization=%s;expires=%s;techniques=%s;max_requests_per_host=%d;max_concurrency=%d;minimum_request_delay_ms=%d",
			cfg.Scope.Authorization, cfg.ActiveTesting.AuthorizationExpires,
			strings.Join(cfg.ActiveTesting.AllowedTechniques, ","),
			cfg.ActiveTesting.MaxRequestsPerHost, cfg.ActiveTesting.MaxConcurrency,
			cfg.ActiveTesting.MinimumRequestDelayMS)
		if err := store.NewAuditLogger(e.db).LogAction(ctx, cfg.ActiveTesting.Operator, "active_testing_authorized", scanID, details); err != nil {
			_ = e.db.FinishScan(ctx, scanID, "failed", err.Error())
			return fmt.Errorf("record active-testing authorization: %w", err)
		}
	}

	queue := scheduler.New(
		cfg.Scheduler.Concurrency,
		time.Duration(cfg.Scheduler.GlobalRateLimitMS)*time.Millisecond,
		time.Duration(cfg.Scheduler.PerTargetRateLimitMS)*time.Millisecond,
		time.Duration(cfg.Scheduler.ModuleTimeoutMS)*time.Millisecond,
		logging.New(),
	)
	if cfg.Scheduler.EnableAdaptiveWorkers {
		queue.EnableAdaptiveWorkers(cfg.Scheduler.MinConcurrency)
	}
	queue.SetScanID(scanID)
	if config.ModuleEnabled(cfg, config.ModuleDiscovery) {
		queue.Register(modules.NewDiscovery(e.db, guard, cfg.Discovery))
		queue.Register(modules.NewReenumeration(guard))
		queue.Register(modules.NewIPv6Discovery(e.db, guard))
		queue.Register(modules.NewARPDiscovery(e.db, guard))
		queue.Register(modules.NewVHostDiscovery(e.db, guard))
		if len(cfg.Discovery.HistoricalURLFiles) > 0 {
			queue.Register(modules.NewHistoricalURLImporter(e.db, guard, cfg.Discovery.HistoricalURLFiles))
		}
	}
	portScanConfig := cfg.PortScan
	if len(cfg.Scan.Ports) > 0 && len(portScanConfig.TCPPorts) == 0 {
		portScanConfig.TCPPorts = cfg.Scan.Ports
	}
	if config.ModuleEnabled(cfg, config.ModulePortScan) {
		queue.Register(modules.NewPortScan(e.db, guard, portScanConfig))
	}
	if config.ModuleEnabled(cfg, config.ModulePortScan) && portScanConfig.EnableRawScanning {
		techniques, err := authorizedRawTechniques(portScanConfig.RawTechniques)
		if err != nil {
			_ = e.db.FinishScan(ctx, scanID, "failed", err.Error())
			return err
		}
		for _, technique := range techniques {
			queue.Register(modules.NewRawTCPScannerWithConfig(e.db, guard, portScanConfig, technique))
		}
	}
	if config.ModuleEnabled(cfg, config.ModuleService) {
		queue.Register(modules.NewServiceFingerprint(e.db, guard))
		queue.Register(modules.NewKerberosADFingerprint(e.db, guard))
		queue.Register(modules.NewSNMPWalkFingerprint(e.db, guard))
		queue.Register(modules.NewOSStackFingerprint(e.db, guard))
		queue.Register(modules.NewTLSFingerprinter(e.db, guard))
	}
	if config.ModuleEnabled(cfg, config.ModuleHTTP) {
		queue.Register(modules.NewHTTP(e.db, guard, cfg.HTTP))
		if cfg.HTTP.EnableScreenshots {
			queue.Register(modules.NewBrowserScreenshotRendererWithConfig(e.db, guard, cfg.HTTP))
		}
		if cfg.HTTP.EnableDirectoryAPI {
			queue.Register(modules.NewDirectoryAPIEnumerator(e.db, guard, cfg.HTTP))
		}
		queue.Register(modules.NewHTTP2FingerprinterWithHTTP3(e.db, guard, cfg.HTTP.EnableHTTP3))
		queue.Register(modules.NewFaviconFingerprinter(e.db, guard))
		queue.Register(modules.NewFrontendFrameworkDetector(e.db, guard))
		queue.Register(modules.NewWasmAndSPADiscovery(e.db, guard))
		queue.Register(modules.NewCMSEnumerator(e.db, guard))
		queue.Register(modules.NewFrameworkEnumerator(e.db, guard))
		queue.Register(modules.NewEnterpriseAppEnumerator(e.db, guard))
		queue.Register(modules.NewSensitiveExposureScanner(e.db, guard))
		queue.Register(modules.NewAPIProtocolScanner(e.db, guard))
		queue.Register(modules.NewAuthProtocolScanner(e.db, guard))
		queue.Register(modules.NewSessionJWTScanner(e.db, guard))
		queue.Register(modules.NewAuthPoliciesDetector(e.db, guard))
		if cfg.HTTP.EnableGRPCReflection && len(cfg.HTTP.GRPCReflectionPorts) > 0 {
			queue.Register(modules.NewGRPCReflectionEnumerator(e.db, guard, cfg.HTTP))
		}
	}
	if config.ModuleEnabled(cfg, config.ModuleSpecialized) {
		queue.Register(modules.NewSpecialized(e.db, guard, cfg.Specialized))
	}
	if config.ModuleEnabled(cfg, config.ModulePassiveIntel) && cfg.PassiveIntel.Enabled {
		queue.Register(modules.NewPassiveIntel(e.db, guard, cfg.PassiveIntel))
	}
	// Plugin execution is deliberately not part of a production scan yet. The
	// current SDK includes manifest and permission groundwork, but it does not
	// provide a trusted registry, signature policy, or an OS-level sandbox. In
	// particular, a scan must never execute files merely because they appear in
	// a local "plugins" directory.

	previous, err := e.db.Events(ctx, scanID)
	if err != nil {
		return err
	}
	for _, event := range previous {
		queue.Enqueue(event)
	}
	for _, target := range cfg.Scan.Targets {
		queue.Enqueue(models.Event{ScanID: scanID, Type: modules.EventTarget, Target: target})
	}
	if err := queue.Run(ctx, e.db); err != nil {
		_ = e.db.FinishScan(ctx, scanID, "failed", err.Error())
		slog.Error("scan failed; operator attention required", "scan_id", scanID, "error", err)
		return err
	}
	if err := e.db.FinishScan(ctx, scanID, "completed", ""); err != nil {
		slog.Error("scan completion could not be persisted; operator attention required", "scan_id", scanID, "error", err)
		return err
	}
	health, err := e.db.ScanHealth(ctx, scanID)
	if err != nil {
		slog.Error("scan health unavailable; operator attention required", "scan_id", scanID, "error", err)
		return err
	}
	if !health.Healthy {
		err := fmt.Errorf("scan %s completed with %d failed module runs", scanID, health.FailedRuns)
		_ = e.db.FinishScan(ctx, scanID, "failed", err.Error())
		slog.Error("scan incomplete; operator attention required", "scan_id", scanID, "failed_module_runs", health.FailedRuns)
		return err
	}
	deliverCompletionSubscription(e.db, scanID, cfg)
	return nil
}

func deliverCompletionSubscription(db *store.SQLiteCLI, scanID string, cfg models.Config) {
	if !cfg.Notifications.EnableScanCompletedWebhook {
		return
	}
	if err := reporting.DeliverWebhook(context.Background(), db, scanID, cfg.Notifications.WebhookURL); err != nil {
		slog.Error("scan-completed webhook delivery failed; scan result remains completed", "scan_id", scanID, "error", err)
	} else {
		slog.Info("scan-completed webhook delivered", "scan_id", scanID)
	}
}

// authorizedRawTechniques maps the explicit operator configuration to raw TCP
// methods. Decoy and idle scans are deliberately excluded: they spoof or rely
// on a third party and do not belong in the normal authorized-enumeration
// workflow. An operator receives a clear configuration error rather than a
// silent fallback to SYN.
func authorizedRawTechniques(values []string) ([]modules.ScanTechnique, error) {
	if len(values) == 0 {
		return []modules.ScanTechnique{modules.ScanSYN}, nil
	}
	techniques := make([]modules.ScanTechnique, 0, len(values))
	seen := make(map[modules.ScanTechnique]bool)
	for _, value := range values {
		var technique modules.ScanTechnique
		switch strings.ToUpper(strings.TrimSpace(value)) {
		case "SYN":
			technique = modules.ScanSYN
		case "ACK":
			technique = modules.ScanACK
		case "FIN":
			technique = modules.ScanFIN
		case "NULL":
			technique = modules.ScanNULL
		case "XMAS":
			technique = modules.ScanXMAS
		case "WINDOW":
			technique = modules.ScanWindow
		case "MAIMON":
			technique = modules.ScanMaimon
		case "FRAGMENTED":
			technique = modules.ScanFragmented
		case "DECOY", "IDLE":
			return nil, fmt.Errorf("raw technique %q is excluded from authorized enumeration because it involves third-party spoofing", value)
		default:
			return nil, fmt.Errorf("unknown raw scan technique %q", value)
		}
		if !seen[technique] {
			seen[technique] = true
			techniques = append(techniques, technique)
		}
	}
	return techniques, nil
}
