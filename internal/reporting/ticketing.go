package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"enumscan/internal/models"
)

var (
	ErrInsecureTicketingURL = errors.New("ticketing integrations require secure HTTPS endpoint")
)

// JiraConfig configures outbound Atlassian Jira issue creation.
type JiraConfig struct {
	BaseURL    string `json:"base_url"`
	UserEmail  string `json:"user_email"`
	APIToken   string `json:"api_token"`
	ProjectKey string `json:"project_key"`
	IssueType  string `json:"issue_type"` // e.g. "Bug", "Vulnerability", "Task"
}

// GitHubIssueConfig configures outbound GitHub Issues ticketing.
type GitHubIssueConfig struct {
	BaseURL   string   `json:"base_url,omitempty"`
	RepoOwner string   `json:"repo_owner"`
	RepoName  string   `json:"repo_name"`
	Token     string   `json:"token"`
	Labels    []string `json:"labels"`
}

// SanitizeEvidenceForTicketing ensures no plaintext passwords or secrets leak into ticket bodies.
func SanitizeEvidenceForTicketing(text string) string {
	sensitiveKeys := []string{"password", "secret", "token", "apikey", "api_key", "bearer", "credential"}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, key := range sensitiveKeys {
			if strings.Contains(lower, key) && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				lines[i] = parts[0] + "=[REDACTED]"
			} else if strings.Contains(lower, key) && strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				lines[i] = parts[0] + ": [REDACTED]"
			}
		}
	}
	return strings.Join(lines, "\n")
}

// CreateJiraIssue securely formats and posts a finding to Jira.
func CreateJiraIssue(ctx context.Context, cfg JiraConfig, f models.Finding, client *http.Client) (string, error) {
	parsedURL, err := url.Parse(cfg.BaseURL)
	if err != nil || (!strings.EqualFold(parsedURL.Scheme, "https") && !strings.HasPrefix(parsedURL.Host, "127.0.0.1") && !strings.HasPrefix(parsedURL.Host, "localhost")) {
		return "", ErrInsecureTicketingURL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	issueType := cfg.IssueType
	if issueType == "" {
		issueType = "Bug"
	}

	sanitizedEvidence := SanitizeEvidenceForTicketing(f.Evidence)
	description := fmt.Sprintf("*Asset:* %s\n*Severity:* %s\n*Confidence:* %s\n\n*Evidence:*\n{code}\n%s\n{code}\n\n*Remediation:*\n%s",
		f.Asset, strings.ToUpper(f.Severity), f.Confidence, sanitizedEvidence, f.Remediation)
	if len(f.References) > 0 {
		description += fmt.Sprintf("\n\n*References:*\n%s", strings.Join(f.References, "\n"))
	}

	jiraPayload := map[string]any{
		"fields": map[string]any{
			"project": map[string]string{
				"key": cfg.ProjectKey,
			},
			"summary":     fmt.Sprintf("[Enumscan] %s on %s", f.Title, f.Asset),
			"description": description,
			"issuetype": map[string]string{
				"name": issueType,
			},
		},
	}

	body, _ := json.Marshal(jiraPayload)
	reqURL := fmt.Sprintf("%s/rest/api/2/issue", strings.TrimRight(cfg.BaseURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cfg.UserEmail, cfg.APIToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("jira api returned HTTP %d", resp.StatusCode)
	}

	var respData struct {
		Key string `json:"key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&respData)
	return respData.Key, nil
}

// CreateGitHubIssue formats and posts a finding to GitHub Issues.
func CreateGitHubIssue(ctx context.Context, cfg GitHubIssueConfig, f models.Finding, client *http.Client) (int, string, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	sanitizedEvidence := SanitizeEvidenceForTicketing(f.Evidence)
	bodyMD := fmt.Sprintf("### Vulnerability Finding: %s\n\n- **Affected Asset:** `%s`\n- **Severity:** `%s`\n- **Confidence:** `%s`\n\n#### Evidence\n```\n%s\n```\n\n#### Remediation\n%s\n",
		f.Title, f.Asset, strings.ToUpper(f.Severity), f.Confidence, sanitizedEvidence, f.Remediation)
	if len(f.References) > 0 {
		bodyMD += fmt.Sprintf("\n#### References\n- %s\n", strings.Join(f.References, "\n- "))
	}

	labels := append([]string{"security", "enumscan"}, cfg.Labels...)
	ghPayload := map[string]any{
		"title":  fmt.Sprintf("[Security] %s (%s)", f.Title, f.Asset),
		"body":   bodyMD,
		"labels": labels,
	}

	rawBody, _ := json.Marshal(ghPayload)
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/issues", baseURL, cfg.RepoOwner, cfg.RepoName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(rawBody))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, "", fmt.Errorf("github api returned HTTP %d", resp.StatusCode)
	}

	var respData struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&respData)
	return respData.Number, respData.HTMLURL, nil
}

// NormalizedTicketingPayload creates a vendor-neutral payload for custom webhooks and SIEM/SOAR.
func NormalizedTicketingPayload(f models.Finding, sourceSystem string) map[string]any {
	return map[string]any{
		"source":      sourceSystem,
		"finding_id":  f.ID,
		"scan_id":     f.ScanID,
		"title":       f.Title,
		"severity":    strings.ToLower(f.Severity),
		"confidence":  f.Confidence,
		"asset":       f.Asset,
		"cve":         f.CVE,
		"cwe":         f.CWE,
		"cvss":        f.CVSS,
		"epss":        f.EPSS,
		"evidence":    SanitizeEvidenceForTicketing(f.Evidence),
		"remediation": f.Remediation,
		"references":  f.References,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
}
