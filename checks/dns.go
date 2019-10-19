package checkdanemx

import "github.com/miekg/dns"

// checkDomainState
func checkDomainState(domain string, nameserver string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)

	in, _, err := c.Exchange(m, nameserver)

	if err == nil {
		switch in.MsgHdr.Rcode {
		case dns.RcodeServerFailure:
			return "502, The name server encountered an internal failure while processing this request (SERVFAIL)"
		case dns.RcodeNameError:
			return "503, Some name that ought to exist, does not exist (NXDOMAIN)"
		case dns.RcodeRefused:
			return "505, The name server refuses to perform the specified operation for policy or security reasons (REFUSED)"
		default:
			return "OK"
		}
	} else {
		return "500, 501, DNS server could not be reached"
	}
}
