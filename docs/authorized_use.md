# Authorized-use guidance

Enumscan is for security assessments that you are explicitly authorized to
perform. You are responsible for confirming authorization before any network
action begins.

## Before a scan

- Obtain written authorization that identifies the organization, approved
  targets, assessment period, operator, and allowed activity.
- Configure every approved IP address, CIDR, hostname, and domain in
  `scope.allowed_targets`. Do not use broad public ranges or wildcard scope.
- Choose bounded concurrency, timeouts, request pacing, and a profile
  appropriate to the engagement. Start with the smallest safe profile.
- Run `enumscan validate-config` and review its effective plan before running
  `enumscan run`.
- Keep credentials, cookies, API tokens, and evidence in approved storage. Do
  not place them in source control, command history, or support requests.

## Prohibited use

Do not use Enumscan to access, disrupt, degrade, exploit, persist on, or
exfiltrate from systems without explicit authority. Do not scan targets outside
the configured scope, bypass access controls, or use results to facilitate harm.

## Elevated activity

Raw sockets, authenticated crawling, screenshots, third-party providers,
notifications, distributed agents, and Tier 4 checks are separately gated.
Tier 4 activity additionally requires an unexpired written authorization,
operator identity, an explicit technique allowlist, bounded impact settings,
and the environment-held acknowledgment described in
[Tier 4 active testing](tier4_active_testing.md). A normal scan authorization
does not grant permission for those techniques.

## Stop conditions

Pause the engagement and contact the authorization owner if you observe an
unexpected target, sensitive information outside the agreed handling plan,
production impact, or a material change to scope or authorization. Preserve
only the minimum evidence needed to report the issue and follow the
engagement's incident-handling procedure.

For the full security model, see [Security model](security.md).
