package checkdanemx

import (
	"fmt"
	"strings"
	"time"

	"github.com/binaryfigments/checkdanemx/models"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Run function
func Run(domain string, startnameserver string) (*checkdata.Message, error) {
	msg := new(checkdata.Message)
	nameServer := startnameserver + ":53"
	msg.Question.JobTime = time.Now()
	msg.Question.JobDomain = domain

	// Valid domain name (ASCII or IDN)
	domain, err := idna.ToASCII(domain)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Non ASCII or IDN characters in domain."
		return msg, err
	}

	// Validate
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Domain not OK"
		return msg, err
	}

	// Go check DNS!

	domainstate := checkDomainState(domain, nameServer)
	if domainstate != "OK" {
		// log.Println(domainstate)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = domainstate
		return msg, err
	}

	mxrecords, err := resolveMxTlsa(domain, nameServer)
	msg.Answer.MxRecords = mxrecords
	if msg.Answer.MxRecords == nil {
		fmt.Printf("[X] No MX records found for  %v\n", domain)
	}

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	return msg, err
}

/*
 * Used functions
 * TODO: Rewrite
 */

func resolveMxTlsa(domain string, nameserver string) ([]*checkdata.MxRecords, error) {
	answer := []*checkdata.MxRecords{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver)
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.MX); ok {
			mxs := new(checkdata.MxRecords)
			mxs.Mx = a.Mx
			mxs.Preference = a.Preference

			checktlsamx := "_25._tcp." + strings.TrimSuffix(a.Mx, ".")
			domainmxtlsa, err := resolveTLSARecord(checktlsamx, nameserver)
			if err != nil {
				fmt.Printf("[X] Error checking for TLSA record %v\n", checktlsamx)
				mxs.TLSA = domainmxtlsa
			} else {
				mxs.TLSA = domainmxtlsa
			}

			answer = append(answer, mxs)
		}
	}
	return answer, nil
}

// resolveTLSARecord for checking TLSA
func resolveTLSARecord(record string, nameserver string) (*checkdata.Tlsa, error) {
	answer := new(checkdata.Tlsa)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(record), dns.TypeTLSA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver)
	if err != nil {
		return answer, err
	}
	for _, value := range in.Answer {
		if tlsa, ok := value.(*dns.TLSA); ok {
			answer.Record = record
			answer.Certificate = tlsa.Certificate
			answer.MatchingType = tlsa.MatchingType
			answer.Selector = tlsa.Selector
			answer.Usage = tlsa.Usage
		}
	}
	return answer, nil
}

// checkDomainState
func checkDomainState(domain string, nameserver string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)

Redo:
	in, _, err := c.Exchange(m, nameserver)

	if err == nil {
		switch in.MsgHdr.Rcode {
		case dns.RcodeServerFailure:
			return "500, 502, The name server encountered an internal failure while processing this request (SERVFAIL)"
		case dns.RcodeNameError:
			return "500, 503, Some name that ought to exist, does not exist (NXDOMAIN)"
		case dns.RcodeRefused:
			return "500, 505, The name server refuses to perform the specified operation for policy or security reasons (REFUSED)"
		default:
			return "OK"
		}
	} else if err == dns.ErrTruncated {
		c.Net = "tcp"
		goto Redo
	} else {
		return "500, 501, DNS server could not be reached"
	}
}
