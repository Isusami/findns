package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// EDNSCheck tests which EDNS payload sizes a resolver supports.
// This is critical for DNSTT — larger payloads = faster tunnel.
// Tests sizes 512, 900, 1232 and reports the largest that works.
func EDNSCheck(domain string, count int) CheckFunc {
	// Build test payloads up to the configured buffer size
	var payloads []int
	for _, p := range []int{512, 900, 1232, 1452, 4096} {
		if p <= int(EDNSBufSize) {
			payloads = append(payloads, p)
		}
	}
	if len(payloads) == 0 || payloads[len(payloads)-1] != int(EDNSBufSize) {
		payloads = append(payloads, int(EDNSBufSize))
	}

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		bestPayload := 0

		for _, payload := range payloads {
			ok := testEDNSPayload(ip, domain, uint16(payload), timeout, count)
			if ok {
				bestPayload = payload
			}
		}

		if bestPayload == 0 {
			return false, nil
		}

		return true, Metrics{"edns_max": float64(bestPayload)}
	}
}

func testEDNSPayload(resolver, domain string, payload uint16, timeout time.Duration, tries int) bool {
	successes := 0

	for i := 0; i < tries; i++ {
		// Use a random subdomain to avoid caching
		qname := fmt.Sprintf("edns-%s.%s", randLabel(8), domain)

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
		m.RecursionDesired = true

		// Set EDNS0 with specified payload size
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(payload)
		m.Extra = append(m.Extra, o)

		c := new(dns.Client)
		c.Net = "udp"
		c.Timeout = timeout

		addr := net.JoinHostPort(resolver, "53")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		r, _, err := c.ExchangeContext(ctx, m, addr)

		if err != nil || r == nil {
			cancel()
			continue
		}

		// If EDNS0 caused FORMERR, retry without it
		if r.Rcode == dns.RcodeFormatError {
			m.Extra = nil
			r, _, err = c.ExchangeContext(ctx, m, addr)
			if err != nil || r == nil {
				cancel()
				continue
			}
		}
		cancel()

		// NOERROR or NXDOMAIN both count as "resolver handled it"
		if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
			successes++
		}
	}

	return successes >= max(1, tries/2)
}
