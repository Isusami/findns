package scanner

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EDNSBufSize is the EDNS0 UDP payload size advertised in queries.
// Larger values allow bigger DNS responses (better tunnel throughput).
// Default 1232 is safe for most networks; lower if you hit fragmentation.
var EDNSBufSize uint16 = 1232

// queryRaw sends a DNS query and handles EDNS0 + TCP fallback on truncation.
// Returns the response regardless of Rcode, so callers can inspect Authority section.
func queryRaw(resolver, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	m.SetEdns0(EDNSBufSize, false)

	addr := net.JoinHostPort(resolver, "53")

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout

	// Use a deadline so all retries share a generous overall budget
	deadline := time.Now().Add(timeout * 2)

	remaining := func() time.Duration {
		d := time.Until(deadline)
		if d < 500*time.Millisecond {
			return 500 * time.Millisecond
		}
		return d
	}

	ctx, cancel := context.WithTimeout(context.Background(), remaining())
	r, _, err := c.ExchangeContext(ctx, m, addr)
	cancel()

	// ednsRetry strips the EDNS0 OPT record and retries the query.
	// Returns true if the retry produced a better response.
	ednsRetry := func() bool {
		savedExtra := m.Extra
		m.Extra = nil
		ctx, cancel = context.WithTimeout(context.Background(), remaining())
		r2, _, err2 := c.ExchangeContext(ctx, m, addr)
		cancel()
		if err2 == nil && r2 != nil {
			r, err = r2, nil
			return true // EDNS0 was the problem; keep it stripped
		}
		m.Extra = savedExtra // retry didn't help; restore
		return false
	}

	// If EDNS0 caused an error response, retry without it.
	// Some servers (e.g. dnstm) return NXDOMAIN instead of FORMERR
	// when they don't understand the OPT record.
	if err == nil && r != nil && r.Rcode != dns.RcodeSuccess {
		ednsRetry()
	}

	// If UDP failed entirely, try TCP before giving up
	if err != nil || r == nil {
		c.Net = "tcp"
		ctx, cancel = context.WithTimeout(context.Background(), remaining())
		r, _, err = c.ExchangeContext(ctx, m, addr)
		cancel()
		if err != nil || r == nil {
			// TCP with EDNS0 also failed; last resort: TCP without EDNS0
			m.Extra = nil
			ctx, cancel = context.WithTimeout(context.Background(), remaining())
			r, _, err = c.ExchangeContext(ctx, m, addr)
			cancel()
			if err != nil || r == nil {
				return nil, false
			}
		}
		// TCP succeeded but got error Rcode; try without EDNS0
		// Skip if EDNS0 was already stripped (m.Extra is nil from line 71)
		if r != nil && r.Rcode != dns.RcodeSuccess && len(m.Extra) > 0 {
			ednsRetry()
		}
	}

	// Retry over TCP if response was truncated
	if r.Truncated {
		c.Net = "tcp"
		ctx, cancel = context.WithTimeout(context.Background(), remaining())
		r, _, err = c.ExchangeContext(ctx, m, addr)
		cancel()
		if err != nil || r == nil {
			return nil, false
		}
	}

	return r, true
}

func query(resolver, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	r, ok := queryRaw(resolver, domain, qtype, timeout)
	if !ok || r.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	return r, true
}

func QueryA(resolver, domain string, timeout time.Duration) bool {
	r, ok := query(resolver, domain, dns.TypeA, timeout)
	if !ok {
		return false
	}
	return len(r.Answer) > 0
}

func QueryNS(resolver, domain string, timeout time.Duration) ([]string, bool) {
	// Strategy 1: direct NS query — works when the recursive resolver returns
	// the delegation NS in Answer or Authority.
	r, ok := queryRaw(resolver, domain, dns.TypeNS, timeout)
	if ok {
		var hosts []string
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				hosts = append(hosts, ns.Ns)
			}
		}
		if len(hosts) == 0 {
			for _, ans := range r.Ns {
				if ns, ok := ans.(*dns.NS); ok {
					hosts = append(hosts, ns.Ns)
				}
			}
		}
		if len(hosts) > 0 {
			return hosts, true
		}
	}

	// Strategy 2: query the parent zone's authoritative nameservers directly.
	// For "t.example.com", find NS of "example.com", then ask those servers
	// for NS of "t.example.com".  This is how subdomain delegation actually
	// works in the DNS hierarchy.
	parent := parentZone(domain)
	if parent == "" {
		return nil, false
	}
	// Get parent zone NS from the resolver
	pr, pok := queryRaw(resolver, parent, dns.TypeNS, timeout)
	if !pok {
		return nil, false
	}
	var parentNS []string
	for _, ans := range pr.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			parentNS = append(parentNS, ns.Ns)
		}
	}
	if len(parentNS) == 0 {
		return nil, false
	}

	// Resolve the first parent NS to an IP and query it directly
	for _, nsHost := range parentNS {
		nsHost = strings.TrimSuffix(nsHost, ".")
		// Resolve the NS hostname to an IP via the same resolver
		ar, aok := queryRaw(resolver, nsHost, dns.TypeA, timeout)
		if !aok {
			continue
		}
		var nsIP string
		for _, ans := range ar.Answer {
			if a, ok := ans.(*dns.A); ok {
				nsIP = a.A.String()
				break
			}
		}
		if nsIP == "" {
			continue
		}
		// Ask the parent's authoritative NS for the subdomain's NS records
		dr, dok := queryRaw(nsIP, domain, dns.TypeNS, timeout)
		if !dok {
			continue
		}
		var hosts []string
		for _, ans := range dr.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				hosts = append(hosts, ns.Ns)
			}
		}
		if len(hosts) == 0 {
			for _, ans := range dr.Ns {
				if ns, ok := ans.(*dns.NS); ok {
					hosts = append(hosts, ns.Ns)
				}
			}
		}
		if len(hosts) > 0 {
			return hosts, true
		}
	}
	return nil, false
}

// parentZone returns the parent zone of a domain.
// e.g. "t.example.com" → "example.com", "example.com" → "com"
// Returns "" if the domain has no parent (is a TLD or empty).
func parentZone(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 || parts[1] == "" {
		return ""
	}
	return parts[1]
}
