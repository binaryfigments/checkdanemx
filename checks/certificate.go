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

func getCertInfo(server string, selector uint8, matchtype uint8) (*checkdata.CertInfo, error) {
	answer := new(checkdata.CertInfo)

	smtpcert, err := runSMTP(server)
	if err != nil {
		println(err)
		return answer, err
	}

	// Selector 0 = cert, 1 = SPKI

	switch selector {
	case 0:
		// MatchingType 0 = cert, 1 = sha256, 2 = sha512
		switch matchtype {
		case 0:
			answer.DaneKey = hex.EncodeToString(smtpcert[0].Raw)
		case 1:
			sh256 := sha256.New()
			sh256.Write(smtpcert[0].Raw)
			sh256sum := hex.EncodeToString(sh256.Sum(nil))
			answer.DaneKey = sh256sum
		case 2:
			sh512 := sha512.New()
			sh512.Write(smtpcert[0].Raw)
			sh512sum := hex.EncodeToString(sh512.Sum(nil))
			answer.DaneKey = sh512sum
		}
	case 1:
		// MatchingType 0 = cert, 1 = sha256, 2 = sha512
		switch matchtype {
		case 0:
			answer.DaneKey = hex.EncodeToString(smtpcert[0].RawSubjectPublicKeyInfo)
		case 1:
			sh256 := sha256.New()
			sh256.Write(smtpcert[0].RawSubjectPublicKeyInfo)
			sh256sum := hex.EncodeToString(sh256.Sum(nil))
			answer.DaneKey = sh256sum
		case 2:
			sh512 := sha512.New()
			sh512.Write(smtpcert[0].RawSubjectPublicKeyInfo)
			sh512sum := hex.EncodeToString(sh512.Sum(nil))
			answer.DaneKey = sh512sum
		}
	}

	answer.CommonName = smtpcert[0].Subject.CommonName

	return answer, nil
}

// runSMTP function for starting the check
func runSMTP(server string) ([]*x509.Certificate, error) {
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

	return cs.PeerCertificates, nil
}
