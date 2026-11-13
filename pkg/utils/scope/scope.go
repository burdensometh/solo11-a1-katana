package scope

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Reason explains why a URL was rejected (or allowed) by scope validation.
// The string values are stable identifiers written out with crawl results and
// emitted in per-target scope statistics, so they must not be renamed without
// updating consumers.
type Reason string

const (
	// ReasonAllowed is returned for URLs that pass every scope check.
	ReasonAllowed Reason = ""
	// ReasonOutOfBound is returned when a URL fails DNS/host scope or the
	// configured in-scope/out-of-scope URL patterns.
	ReasonOutOfBound Reason = "scope_out_of_bound"
	// ReasonPathFiltered is returned when a URL is rejected by the extension /
	// path filter (checked at the crawler layer rather than in Manager).
	ReasonPathFiltered Reason = "scope_path_filtered"
	// ReasonDepthExceeded is returned when a URL is discovered beyond the
	// configured maximum crawl depth.
	ReasonDepthExceeded Reason = "scope_depth_exceeded"
)

// Manager manages scope for crawling process
type Manager struct {
	inScope           []*regexp.Regexp
	outOfScope        []*regexp.Regexp
	noScope           bool
	fieldScope        dnsScopeField
	fieldScopePattern *regexp.Regexp
}

type dnsScopeField int

const (
	dnDnsScopeField dnsScopeField = iota + 1
	rdnDnsScopeField
	fqdnDNSScopeField
	customDNSScopeField
)

var stringToDNSScopeField = map[string]dnsScopeField{
	"dn":   dnDnsScopeField,
	"rdn":  rdnDnsScopeField,
	"fqdn": fqdnDNSScopeField,
}

// NewManager returns a new scope manager for crawling
func NewManager(inScope, outOfScope []string, fieldScope string, noScope bool) (*Manager, error) {
	manager := &Manager{
		noScope: noScope,
	}

	if scopeValue, ok := stringToDNSScopeField[fieldScope]; !ok {
		manager.fieldScope = customDNSScopeField
		if compiled, err := regexp.Compile(fieldScope); err != nil {
			return nil, fmt.Errorf("could not compile regex %s: %s", fieldScope, err)
		} else {
			manager.fieldScopePattern = compiled
		}
	} else {
		manager.fieldScope = scopeValue
	}
	for _, regex := range inScope {
		if compiled, err := regexp.Compile(regex); err != nil {
			return nil, fmt.Errorf("could not compile regex %s: %s", regex, err)
		} else {
			manager.inScope = append(manager.inScope, compiled)
		}
	}
	for _, regex := range outOfScope {
		if compiled, err := regexp.Compile(regex); err != nil {
			return nil, fmt.Errorf("could not compile regex %s: %s", regex, err)
		} else {
			manager.outOfScope = append(manager.outOfScope, compiled)
		}
	}
	return manager, nil
}

// Validate returns true if the URL matches scope rules.
// When noScope is true, DNS validation is skipped but URL-based scope rules still apply.
// It is a convenience wrapper around ValidateWithReason for callers that do not
// need the rejection reason.
func (m *Manager) Validate(URL *url.URL, rootHostname string) (bool, error) {
	validated, _, err := m.ValidateWithReason(URL, rootHostname)
	return validated, err
}

// ValidateWithReason behaves like Validate but additionally returns the Reason
// explaining the decision: ReasonAllowed when the URL passes every check, or
// ReasonOutOfBound when host (DNS) or URL-pattern scope rejects it.
func (m *Manager) ValidateWithReason(URL *url.URL, rootHostname string) (bool, Reason, error) {
	if !m.noScope {
		// Only validate DNS if scope is enabled
		hostname := URL.Hostname()
		dnsValidated, err := m.validateDNS(hostname, rootHostname)
		if err != nil {
			return false, ReasonOutOfBound, err
		}
		if !dnsValidated {
			return false, ReasonOutOfBound, nil
		}
	}

	if len(m.inScope) > 0 || len(m.outOfScope) > 0 {
		urlValidated, err := m.validateURL(URL.String())
		if err != nil {
			return false, ReasonOutOfBound, err
		}
		if !urlValidated {
			return false, ReasonOutOfBound, nil
		}
	}

	return true, ReasonAllowed, nil
}

// validateURL checks whether the given URL matches the configured inScope and outOfScope patterns.
// It returns true if the URL is allowed (matches inScope and doesn't match outOfScope),
// false if rejected, and an error if pattern matching fails.
// When both inScope and outOfScope are empty, it returns true with no error.
func (m *Manager) validateURL(URL string) (bool, error) {
	for _, item := range m.outOfScope {
		if item.MatchString(URL) {
			return false, nil
		}
	}
	if len(m.inScope) == 0 {
		return true, nil
	}

	var inScopeMatched bool
	for _, item := range m.inScope {
		if item.MatchString(URL) {
			inScopeMatched = true
			break
		}
	}
	return inScopeMatched, nil
}

// validateDNS performs DNS-based scope validation by checking if the URL's hostname
// matches the configured host-based scope rules. It returns true if the hostname
// is within scope, false if out of scope, and an error if DNS resolution or
// validation fails.
func (m *Manager) validateDNS(hostname, rootHostname string) (bool, error) {
	parsed := net.ParseIP(hostname)
	if m.fieldScope == customDNSScopeField {
		// If we have a custom regex, we need to match it against the full hostname
		if m.fieldScopePattern.MatchString(hostname) {
			return true, nil
		}
	}
	if m.fieldScope == fqdnDNSScopeField || parsed != nil {
		matched := strings.EqualFold(hostname, rootHostname)
		return matched, nil
	}

	rdn, dn, err := getDomainRDNandRDN(rootHostname)
	if err != nil {
		return false, err
	}
	switch m.fieldScope {
	case dnDnsScopeField:
		// dn is a domain-name keyword scope (see the -field-scope docs): any host
		// whose name contains the keyword is in scope. DNS is case-insensitive, so
		// compare without regard to case (the fqdn path above already uses EqualFold).
		return strings.Contains(strings.ToLower(hostname), strings.ToLower(dn)), nil
	case rdnDnsScopeField:
		// Match the registrable domain itself or any of its subdomains. A label
		// boundary is required so look-alike domains that merely share the root as
		// a string suffix (e.g. evilexample.com vs example.com) are not in scope.
		return matchesDomainOrSubdomain(hostname, rdn), nil
	}
	return false, nil
}

// matchesDomainOrSubdomain reports whether host equals domain or is one of its
// subdomains (i.e. host ends with "."+domain). Matching is case-insensitive
// because DNS labels are case-insensitive. Requiring the leading dot enforces a
// label boundary, so look-alike hosts that only share domain as a raw string
// suffix (e.g. evilexample.com vs example.com) are not considered in scope.
func matchesDomainOrSubdomain(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// getDomainRDNandRDN extracts and returns the root domain name (RDN) and the
// effective top-level domain plus one label (eTLD+1) from the given hostname.
// It returns empty strings and an error if the hostname cannot be parsed.
func getDomainRDNandRDN(domain string) (string, string, error) {
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", "", fmt.Errorf("publicsuffix: empty label in domain %q", domain)
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	if len(domain) <= len(suffix) {
		return domain, "", nil
	}
	i := len(domain) - len(suffix) - 1
	if domain[i] != '.' {
		return domain, "", nil
	}
	return domain[1+strings.LastIndex(domain[:i], "."):], domain[1+strings.LastIndex(domain[:i], ".") : len(domain)-len(suffix)-1], nil
}
