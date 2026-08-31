package reporting

import (
	"regexp"
)

var (
	awsAccessKeyRegex  = regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`)
	jwtTokenRegex      = regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`)
	privateKeyRegex    = regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----[\s\S]*?-----END (RSA|EC|OPENSSH|PRIVATE) KEY-----`)
	bearerHeaderRegex  = regexp.MustCompile(`(?i)(Bearer|Authorization|Token):\s*([^\s,]+)`)
	passwordParamRegex = regexp.MustCompile(`(?i)(password|passwd|secret|api_key|token)=([^&\s]+)`)
)

func RedactSecrets(content string) string {
	if content == "" {
		return content
	}

	result := awsAccessKeyRegex.ReplaceAllString(content, "${1}[REDACTED_AWS_KEY]")
	result = privateKeyRegex.ReplaceAllString(result, "[REDACTED_PRIVATE_KEY]")
	result = jwtTokenRegex.ReplaceAllString(result, "[REDACTED_JWT_TOKEN]")
	result = bearerHeaderRegex.ReplaceAllString(result, "$1: [REDACTED_TOKEN]")
	result = passwordParamRegex.ReplaceAllString(result, "$1=[REDACTED]")

	return result
}
