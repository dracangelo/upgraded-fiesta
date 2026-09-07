# Scanning and modules

Profiles select module families; individual settings control network behavior.
All discovered targets are rechecked against scope.

## Discovery

Discovery supports bounded CIDR expansion, DNS records, reverse and wildcard
DNS, RDAP, optional ICMP/TCP/UDP liveness, IPv6, ARP, virtual hosts, and offline
imports for passive DNS, certificate transparency, packet traits, and historical
URLs. Timeouts are not treated as proof that a host is dead.

## Port and service enumeration

TCP connect and UDP scanning are bounded by configured ports, timeouts, and
per-host concurrency. Banner and protocol responses feed service and CPE
fingerprinting. Raw techniques require explicit configuration and platform
privileges; connect fallback behavior remains evidence-labelled.

## HTTP and TLS

The HTTP pipeline supports bounded crawling, first-party JavaScript analysis,
API discovery, directory enumeration with wildcard baselining, technology
detection, redirect safety, source-map analysis, optional cookie jars,
operator-supplied authenticated sessions, screenshots, HTTP/3 confirmation,
and selected gRPC reflection.

Normal HTTP enumeration sends safe methods and records evidence indicators; it
does not claim active vulnerability exploitation.

## Specialized protocols

Opt-in modules cover SMB/LDAP/SNMP capability discovery, cloud/container and
database endpoints, and read-only SSH/FTP/SMTP capabilities. Configure each
family independently and provide credentials only through environment or
secret-manager references where supported.

## Passive intelligence

Supported providers include VirusTotal, Shodan, Censys, SecurityTrails, FOFA,
Hunter.io, WhoisXML API, Have I Been Pwned, GitHub, GitLab, DNSDB, CIRCL CVE
Search, and configured offline/unauthenticated sources. Provider controls offer
enable overrides, version pins, pacing, retry bounds, quota discovery, and
local or explicit remote diagnostics.

## Findings and prioritization

Imported NVD, Nuclei, OpenVAS, and Nessus evidence can be correlated with CPEs,
KEV, EPSS, and public-exploit indicators. Risk scores, exposure chains, and
recommendations are deterministic and preserve uncertainty.

## Tier 4

Intrusive checks require a second authorization boundary. See
[Tier 4 active testing](tier4_active_testing.md) for technique names and the
honest runner-status matrix.

