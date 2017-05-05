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

	// Get TLSA records and Certs
	for _, mx := range msg.Answer.MxRecords {
		hostname := strings.TrimSuffix(mx.Mx, ".")
		hosnameport := hostname + ":25"
		checktlsamx := "_25._tcp." + hostname

		domainmxtlsa, err := resolveTLSARecords(checktlsamx, nameServer)
		if err != nil {
			mx.TLSA = domainmxtlsa
		} else {
			mx.TLSA = domainmxtlsa

			if checkCerts == "yes" {
				for _, tlsar := range domainmxtlsa {
					certinfo, err := getCertInfo(hosnameport, tlsar.Selector, tlsar.MatchingType)
					if err != nil {
						tlsar.ServerCertificate = certinfo
					} else {
						tlsar.ServerCertificate = certinfo
					}
				}
			}

		}
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

// resolveTLSARecords for checking TLSA
func resolveTLSARecords(record string, nameserver string) ([]*checkdata.Tlsa, error) {
	answer := []*checkdata.Tlsa{}
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
			//
			tlsar := new(checkdata.Tlsa)
			tlsar.Record = record
			tlsar.Certificate = tlsa.Certificate
			tlsar.MatchingType = tlsa.MatchingType
			tlsar.Selector = tlsa.Selector
			tlsar.Usage = tlsa.Usage
			answer = append(answer, tlsar)

			//
		}
	}
	return answer, nil
}
