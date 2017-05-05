package checkdata

import "time"

// Message struct for returning the question and the answer.
type Message struct {
	Question Question `json:"question"`
	Answer   Answer   `json:"answer,omitempty"`
}

// Question struct for retuning what information is asked.
type Question struct {
	JobDomain  string    `json:"domain"`
	JobStatus  string    `json:"status"`
	JobMessage string    `json:"message"`
	JobTime    time.Time `json:"time"`
}

// Answer struct the answer of the question.
type Answer struct {
	MxRecords []*MxRecords `json:"mx,omitempty"`
}

// MxRecords struct for MX records
type MxRecords struct {
	Mx         string  `json:"mx,omitempty"`
	Preference uint16  `json:"preference,omitempty"`
	TLSA       []*Tlsa `json:"tlsa,omitempty"`
	// CertInfo   []*CertInfo `json:"cert,omitempty"`
}

// Tlsa struct for SOA information
type Tlsa struct {
	Record            string    `json:"record"`
	Usage             uint8     `json:"usage"`
	Selector          uint8     `json:"selector"`
	MatchingType      uint8     `json:"matchingtype"`
	Certificate       string    `json:"certificate"`
	ServerCertificate *CertInfo `json:"server_certificate,omitempty"`
}

// CertInfo struct for certificate information
type CertInfo struct {
	CommonName  string `json:"common_name,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}
