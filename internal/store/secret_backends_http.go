package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type httpSecretsBackend struct {
	config   SecretsManagerConfig
	endpoint *url.URL
}

func newHTTPSecretsBackend(config SecretsManagerConfig) (*httpSecretsBackend, error) {
	if config.TokenEnv != "" && config.TokenFile != "" {
		return nil, fmt.Errorf("configure only one of token_env or token_file")
	}
	if config.Provider == ProviderAWS && strings.TrimSpace(config.Endpoint) == "" {
		if strings.TrimSpace(config.Region) == "" {
			return nil, fmt.Errorf("AWS Secrets Manager requires a region")
		}
		config.Endpoint = "https://secretsmanager." + config.Region + ".amazonaws.com"
	}
	if config.Provider == ProviderGCP && strings.TrimSpace(config.Endpoint) == "" {
		config.Endpoint = "https://secretmanager.googleapis.com"
	}
	endpoint, err := url.Parse(strings.TrimRight(strings.TrimSpace(config.Endpoint), "/"))
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("secret backend %q requires a valid endpoint", config.Provider)
	}
	if endpoint.Scheme != "https" {
		host := endpoint.Hostname()
		ip := net.ParseIP(host)
		if endpoint.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("secret backend endpoint must use HTTPS outside loopback tests")
		}
	}
	switch config.Provider {
	case ProviderVault:
		if config.TokenEnv == "" && config.TokenFile == "" {
			return nil, fmt.Errorf("Vault requires token_env or token_file")
		}
		if config.Mount == "" {
			config.Mount = "secret"
		}
	case ProviderK8s:
		if (config.TokenEnv == "" && config.TokenFile == "") || config.Namespace == "" {
			return nil, fmt.Errorf("Kubernetes secrets require token_env or token_file, plus namespace")
		}
	case ProviderAzure:
		if config.TokenEnv == "" && config.TokenFile == "" {
			return nil, fmt.Errorf("Azure Key Vault requires token_env or token_file")
		}
	case ProviderGCP:
		if (config.TokenEnv == "" && config.TokenFile == "") || config.Project == "" {
			return nil, fmt.Errorf("GCP Secret Manager requires token_env or token_file, plus project")
		}
	case ProviderAWS:
		if config.Region == "" {
			return nil, fmt.Errorf("AWS Secrets Manager requires region")
		}
	}
	return &httpSecretsBackend{config: config, endpoint: endpoint}, nil
}

func (b *httpSecretsBackend) GetSecret(ctx context.Context, key string) (string, error) {
	if err := validateExternalSecretKey(key); err != nil {
		return "", err
	}
	switch b.config.Provider {
	case ProviderVault:
		return b.vaultGet(ctx, key)
	case ProviderK8s:
		return b.kubernetesGet(ctx, key)
	case ProviderAWS:
		return b.awsGet(ctx, key)
	case ProviderAzure:
		return b.azureGet(ctx, key)
	case ProviderGCP:
		return b.gcpGet(ctx, key)
	}
	return "", fmt.Errorf("unsupported secret backend")
}
func (b *httpSecretsBackend) SetSecret(ctx context.Context, key, value string) error {
	if err := validateSecretWrite(key, value); err != nil {
		return err
	}
	switch b.config.Provider {
	case ProviderVault:
		return b.vaultSet(ctx, key, value)
	case ProviderK8s:
		return b.kubernetesSet(ctx, key, value)
	case ProviderAWS:
		return b.awsSet(ctx, key, value)
	case ProviderAzure:
		return b.azureSet(ctx, key, value)
	case ProviderGCP:
		return b.gcpSet(ctx, key, value)
	}
	return fmt.Errorf("unsupported secret backend")
}
func (b *httpSecretsBackend) RotateSecret(ctx context.Context, key, value string) error {
	return b.SetSecret(ctx, key, value)
}

func (b *httpSecretsBackend) request(ctx context.Context, method, requestPath string, body any, headers map[string]string) ([]byte, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	endpoint := *b.endpoint
	relative, err := url.Parse(requestPath)
	if err != nil {
		return nil, err
	}
	endpoint.Path = path.Join(b.endpoint.Path, relative.Path)
	endpoint.RawQuery = relative.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := b.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request secret backend: %w", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("secret backend returned HTTP %d", resp.StatusCode)
	}
	return data, nil
}
func requiredEnv(name string) (string, error) {
	value := os.Getenv(name)
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("required credential environment variable %s is empty", name)
	}
	return value, nil
}

func (b *httpSecretsBackend) credential() (string, error) {
	if b.config.TokenFile == "" {
		return requiredEnv(b.config.TokenEnv)
	}
	info, err := os.Stat(b.config.TokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64*1024 {
		return "", fmt.Errorf("credential token file is unavailable or outside size bounds")
	}
	data, err := os.ReadFile(b.config.TokenFile)
	if err != nil {
		return "", fmt.Errorf("read credential token file: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("credential token file must contain one non-empty line")
	}
	return value, nil
}

func (b *httpSecretsBackend) vaultHeaders() (map[string]string, error) {
	token, err := b.credential()
	if err != nil {
		return nil, err
	}
	return map[string]string{"X-Vault-Token": token}, nil
}
func (b *httpSecretsBackend) vaultGet(ctx context.Context, key string) (string, error) {
	headers, err := b.vaultHeaders()
	if err != nil {
		return "", err
	}
	data, err := b.request(ctx, http.MethodGet, "v1/"+b.config.Mount+"/data/"+key, nil, headers)
	if err != nil {
		return "", err
	}
	var response struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &response) != nil || response.Data.Data["value"] == "" {
		return "", fmt.Errorf("Vault response contained no value")
	}
	return response.Data.Data["value"], nil
}
func (b *httpSecretsBackend) vaultSet(ctx context.Context, key, value string) error {
	headers, err := b.vaultHeaders()
	if err != nil {
		return err
	}
	_, err = b.request(ctx, http.MethodPost, "v1/"+b.config.Mount+"/data/"+key, map[string]any{"data": map[string]string{"value": value}}, headers)
	return err
}

func (b *httpSecretsBackend) bearerHeaders() (map[string]string, error) {
	token, err := b.credential()
	if err != nil {
		return nil, err
	}
	return map[string]string{"Authorization": "Bearer " + token}, nil
}
func (b *httpSecretsBackend) kubernetesGet(ctx context.Context, key string) (string, error) {
	headers, err := b.bearerHeaders()
	if err != nil {
		return "", err
	}
	data, err := b.request(ctx, http.MethodGet, "api/v1/namespaces/"+b.config.Namespace+"/secrets/"+key, nil, headers)
	if err != nil {
		return "", err
	}
	var response struct {
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal(data, &response) != nil {
		return "", fmt.Errorf("invalid Kubernetes Secret response")
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Data["value"])
	if err != nil || len(decoded) == 0 {
		return "", fmt.Errorf("Kubernetes Secret contained no valid value field")
	}
	return string(decoded), nil
}
func (b *httpSecretsBackend) kubernetesSet(ctx context.Context, key, value string) error {
	headers, err := b.bearerHeaders()
	if err != nil {
		return err
	}
	headers["Content-Type"] = "application/merge-patch+json"
	_, err = b.request(ctx, http.MethodPatch, "api/v1/namespaces/"+b.config.Namespace+"/secrets/"+key, map[string]any{"data": map[string]string{"value": base64.StdEncoding.EncodeToString([]byte(value))}}, headers)
	return err
}

func (b *httpSecretsBackend) azureGet(ctx context.Context, key string) (string, error) {
	headers, err := b.bearerHeaders()
	if err != nil {
		return "", err
	}
	data, err := b.request(ctx, http.MethodGet, "secrets/"+key+"?api-version=7.4", nil, headers)
	if err != nil {
		return "", err
	}
	var response struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(data, &response) != nil || response.Value == "" {
		return "", fmt.Errorf("Azure Key Vault response contained no value")
	}
	return response.Value, nil
}
func (b *httpSecretsBackend) azureSet(ctx context.Context, key, value string) error {
	headers, err := b.bearerHeaders()
	if err != nil {
		return err
	}
	_, err = b.request(ctx, http.MethodPut, "secrets/"+key+"?api-version=7.4", map[string]string{"value": value}, headers)
	return err
}

func (b *httpSecretsBackend) gcpGet(ctx context.Context, key string) (string, error) {
	headers, err := b.bearerHeaders()
	if err != nil {
		return "", err
	}
	data, err := b.request(ctx, http.MethodGet, "v1/projects/"+b.config.Project+"/secrets/"+key+"/versions/latest:access", nil, headers)
	if err != nil {
		return "", err
	}
	var response struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if json.Unmarshal(data, &response) != nil {
		return "", fmt.Errorf("invalid GCP Secret Manager response")
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Payload.Data)
	if err != nil || len(decoded) == 0 {
		return "", fmt.Errorf("GCP Secret Manager response contained no value")
	}
	return string(decoded), nil
}
func (b *httpSecretsBackend) gcpSet(ctx context.Context, key, value string) error {
	headers, err := b.bearerHeaders()
	if err != nil {
		return err
	}
	_, err = b.request(ctx, http.MethodPost, "v1/projects/"+b.config.Project+"/secrets/"+key+":addVersion", map[string]any{"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(value))}}, headers)
	return err
}

func (b *httpSecretsBackend) awsGet(ctx context.Context, key string) (string, error) {
	data, err := b.awsRequest(ctx, "secretsmanager.GetSecretValue", map[string]string{"SecretId": key})
	if err != nil {
		return "", err
	}
	var response struct{ SecretString string }
	if json.Unmarshal(data, &response) != nil || response.SecretString == "" {
		return "", fmt.Errorf("AWS Secrets Manager response contained no SecretString")
	}
	return response.SecretString, nil
}
func (b *httpSecretsBackend) awsSet(ctx context.Context, key, value string) error {
	_, err := b.awsRequest(ctx, "secretsmanager.PutSecretValue", map[string]string{"SecretId": key, "SecretString": value})
	return err
}
func (b *httpSecretsBackend) awsRequest(ctx context.Context, target string, body any) ([]byte, error) {
	access, err := requiredEnv("AWS_ACCESS_KEY_ID")
	if err != nil {
		return nil, err
	}
	secret, err := requiredEnv("AWS_SECRET_ACCESS_KEY")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := sha256Hex(payload)
	canonicalHeaders := "content-type:application/x-amz-json-1.1\nhost:" + b.endpoint.Host + "\nx-amz-date:" + amzDate + "\nx-amz-target:" + target + "\n"
	signedHeaders := "content-type;host;x-amz-date;x-amz-target"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
	scope := date + "/" + b.config.Region + "/secretsmanager/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	signingKey := awsHMAC(awsHMAC(awsHMAC(awsHMAC([]byte("AWS4"+secret), date), b.config.Region), "secretsmanager"), "aws4_request")
	signature := hex.EncodeToString(awsHMAC(signingKey, stringToSign))
	headers := map[string]string{"X-Amz-Date": amzDate, "X-Amz-Target": target, "Authorization": "AWS4-HMAC-SHA256 Credential=" + access + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature}
	if token := os.Getenv("AWS_SESSION_TOKEN"); token != "" {
		headers["X-Amz-Security-Token"] = token
	}
	return b.request(ctx, http.MethodPost, "/", json.RawMessage(payload), headers)
}
func awsHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
func sha256Hex(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
