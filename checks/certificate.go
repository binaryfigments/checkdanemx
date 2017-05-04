package checkdanemx

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"

	"github.com/binaryfigments/checkdanemx/models"
)

func getCertInfo(server string) (*checkdata.CertInfo, error) {
	answer := new(checkdata.CertInfo)

	smtpcert, err := runSMTP(server)
	if err != nil {
		println(err)
		return answer, err
	}
	// fmt.Fprintf(os.Stderr, "%v\n\n", smtpcert.Answer.PeerCertificates.Subject.CommonName)

	sh256 := sha256.New()
	sh256.Write(smtpcert.RawSubjectPublicKeyInfo)
	sh256sum := hex.EncodeToString(sh256.Sum(nil))
	println(sh256sum)

	sh512 := sha512.New()
	sh512.Write(smtpcert.RawSubjectPublicKeyInfo)
	sh512sum := hex.EncodeToString(sh512.Sum(nil))
	println(sh512sum)

	println(smtpcert.RawSubjectPublicKeyInfo)

	answer.CommonName = smtpcert.Subject.CommonName
	answer.SubjectPublicKeyInfoFull = string(smtpcert.RawSubjectPublicKeyInfo)
	answer.SubjectPublicKeyInfoSha256 = sh256sum
	answer.SubjectPublicKeyInfoSha512 = sh512sum

	return answer, nil
}

// runSMTP function for starting the check
func runSMTP(server string) (*x509.Certificate, error) {
	var (
		err error
	)

	host, _, _ := net.SplitHostPort(server)

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	// c, err := tls.DialWithDialer(dialer, "tcp", server, tlsconfig)
	c, err := smtp.Dial(server)
	if err != nil {
		fmt.Printf("[X] Dial error: %v\n", err)
		return nil, err
	}

	c.StartTLS(tlsconfig)

	cs, ok := c.TLSConnectionState()
	if !ok {
		return nil, err
	}
	c.Quit()

	return cs.PeerCertificates[0], nil
}
