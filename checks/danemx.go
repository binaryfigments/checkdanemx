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
func Run(domain string, startnameserver string, checkCerts string) (*checkdata.Message, error) {
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

	// Check DNS!
	domainstate := checkDomainState(domain, nameServer)
	if domainstate != "OK" {
		// log.Println(domainstate)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = domainstate
		return msg, err
	}

	// Get MX records
	mxrecords, err := resolveMxTlsa(domain, nameServer, checkCerts)
	msg.Answer.MxRecords = mxrecords
	if msg.Answer.MxRecords == nil {
		fmt.Printf("[X] No MX records found for  %v\n", domain)
	}

	// Get TLSA records
	for _, mx := range msg.Answer.MxRecords {
		hostname := strings.TrimSuffix(mx.Mx, ".")
		// hosnameport := hostname + ":25"
		checktlsamx := "_25._tcp." + hostname

		records := new(checkdata.Tlsa)

		domainmxtlsa, err := resolveTLSARecord(checktlsamx, nameServer)
		if err != nil {
			records = domainmxtlsa
		} else {
			records = domainmxtlsa
			/*
				if checkCerts == "yes" {
					certinfo, err := getCertInfo(hosnameport, mxs.TLSA.Selector, mxs.TLSA.MatchingType)
					if err != nil {
						mxs.CertInfo = certinfo
					} else {
						mxs.CertInfo = certinfo
					}
				}
			*/
		}
		mx.TLSA = records
	}

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	return msg, err
}

/*
 * Used functions
 * TODO: Rewrite
 */

func resolveMxTlsa(domain string, nameserver string, checkCerts string) ([]*checkdata.MxRecords, error) {
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

			/*
				hostname := strings.TrimSuffix(a.Mx, ".")
				hosnameport := hostname + ":25"
				checktlsamx := "_25._tcp." + hostname
				domainmxtlsa, err := resolveTLSARecord(checktlsamx, nameserver)
				if err != nil {
					mxs.TLSA = domainmxtlsa
				} else {
					mxs.TLSA = domainmxtlsa
					if checkCerts == "yes" {
						certinfo, err := getCertInfo(hosnameport, mxs.TLSA.Selector, mxs.TLSA.MatchingType)
						if err != nil {
							mxs.CertInfo = certinfo
						} else {
							mxs.CertInfo = certinfo
						}
					}
				}
			*/

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

// resolveTLSARecords for checking TLSA
func resolveTLSARecords(record string, nameserver string) (*checkdata.Tlsa, error) {
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
