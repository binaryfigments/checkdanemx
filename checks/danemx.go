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

	for _, mx := range msg.Answer.MxRecords {
		mxhost := strings.TrimSuffix(mx.Mx, ".")
		certinfo, err := getCertInfo(mxhost + ":25")
		if err != nil {
			fmt.Printf("[X] Error getting cert from, %v %v\n", mxhost+":25", err)
		}
		fmt.Printf("[*] Cert1: %s\n", certinfo.CommonName)
		fmt.Printf("[*] Cert1: %x\n", certinfo.SubjectPublicKeyInfoFull)
		fmt.Printf("[*] Cert1: %x\n", certinfo.SubjectPublicKeyInfoSha256)
		fmt.Printf("[*] Cert1: %x\n", certinfo.SubjectPublicKeyInfoSha512)
	}

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	hosnameport := "smtp.xs4all.nl:25"
	certinfo, err := getCertInfo(hosnameport)
	if err != nil {
		fmt.Printf("[X] Error getting cert from, %v %v\n", hosnameport, err)
	}
	fmt.Printf("[*] Cert1: %s\n", certinfo.CommonName)
	fmt.Printf("[*] Cert1: %x\n", certinfo.SubjectPublicKeyInfoFull)
	fmt.Printf("[*] Cert1: %x\n", certinfo.SubjectPublicKeyInfoSha256)
	fmt.Printf("[*] Cert1: %x\n", certinfo.SubjectPublicKeyInfoSha512)

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
			hostname := strings.TrimSuffix(a.Mx, ".")
			//hosnameport := hostname + ":25"

			checktlsamx := "_25._tcp." + hostname
			domainmxtlsa, err := resolveTLSARecord(checktlsamx, nameserver)
			if err != nil {
				fmt.Printf("[X] Error checking for TLSA record %v\n", checktlsamx)
				mxs.TLSA = domainmxtlsa
			} else {
				mxs.TLSA = domainmxtlsa
				/*
					fmt.Printf("[*] Getting certificate from %v\n", hosnameport)
					certinfo, err := getCertInfo(hosnameport)
					if err != nil {
						fmt.Printf("[X] Error getting cert from, %v %v\n", hosnameport, err)
						mxs.CertInfo = certinfo
					}
				*/
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
