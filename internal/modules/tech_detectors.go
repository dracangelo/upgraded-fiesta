package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type CMSEnumerator struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewCMSEnumerator(db *store.SQLiteCLI, guard scope.Guard) *CMSEnumerator {
	return &CMSEnumerator{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *CMSEnumerator) Name() string {
	return "cms_enumerator"
}

func (m *CMSEnumerator) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *CMSEnumerator) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, evt.Target)

	// Probe WordPress indicator
	req, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/wp-json/", nil)
	if resp, err := m.client.Do(req); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "cms",
				Value:    fmt.Sprintf("WordPress on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "wp_json_endpoint",
			})
		}
	}

	// Probe Drupal indicator
	reqDrupal, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/core/CHANGELOG.txt", nil)
	if resp, err := m.client.Do(reqDrupal); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "cms",
				Value:    fmt.Sprintf("Drupal on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "drupal_changelog",
			})
		}
	}

	// Probe Joomla indicator
	reqJoomla, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/administrator/manifests/files/joomla.xml", nil)
	if resp, err := m.client.Do(reqJoomla); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "cms",
				Value:    fmt.Sprintf("Joomla on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "joomla_xml",
			})
		}
	}

	return nil, nil
}

type FrameworkEnumerator struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewFrameworkEnumerator(db *store.SQLiteCLI, guard scope.Guard) *FrameworkEnumerator {
	return &FrameworkEnumerator{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *FrameworkEnumerator) Name() string {
	return "framework_enumerator"
}

func (m *FrameworkEnumerator) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *FrameworkEnumerator) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, evt.Target)

	// Probe Spring Boot Actuator
	reqActuator, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/actuator/health", nil)
	if resp, err := m.client.Do(reqActuator); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "web_framework",
				Value:    fmt.Sprintf("Spring Boot on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "spring_boot_actuator",
			})
		}
	}

	// Probe ASP.NET ELMAH
	reqElmah, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/elmah.axd", nil)
	if resp, err := m.client.Do(reqElmah); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "web_framework",
				Value:    fmt.Sprintf("ASP.NET (ELMAH exposed) on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "aspnet_elmah",
			})
		}
	}

	return nil, nil
}

type EnterpriseAppEnumerator struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewEnterpriseAppEnumerator(db *store.SQLiteCLI, guard scope.Guard) *EnterpriseAppEnumerator {
	return &EnterpriseAppEnumerator{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *EnterpriseAppEnumerator) Name() string {
	return "enterprise_app_enumerator"
}

func (m *EnterpriseAppEnumerator) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *EnterpriseAppEnumerator) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, evt.Target)

	req, _ := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if resp, err := m.client.Do(req); err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if resp.Header.Get("X-Jenkins") != "" || strings.Contains(bodyStr, "adjuncts") {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "enterprise_app",
				Value:    fmt.Sprintf("Jenkins CI on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "jenkins_ci",
			})
		}

		if strings.Contains(bodyStr, "_gitlab_session") || strings.Contains(bodyStr, "GitLab") {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "enterprise_app",
				Value:    fmt.Sprintf("GitLab on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "gitlab_portal",
			})
		}

		if strings.Contains(bodyStr, "Outlook Web App") || strings.Contains(bodyStr, "/owa/") {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "enterprise_app",
				Value:    fmt.Sprintf("Microsoft Exchange OWA on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "exchange_owa",
			})
		}

		if strings.Contains(bodyStr, "Jira") || strings.Contains(bodyStr, "Atlassian") {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "enterprise_app",
				Value:    fmt.Sprintf("Atlassian Jira/Confluence on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "atlassian_jira_confluence",
			})
		}

		if strings.Contains(bodyStr, "ServiceNow") {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "enterprise_app",
				Value:    fmt.Sprintf("ServiceNow Portal on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "servicenow",
			})
		}

		if strings.Contains(bodyStr, "SAP") {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "enterprise_app",
				Value:    fmt.Sprintf("SAP NetWeaver / ERP on %s", evt.Target),
				Parent:   evt.Target,
				Metadata: "sap_erp",
			})
		}
	}

	return nil, nil
}
