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
	Mx         string    `json:"mx,omitempty"`
	Preference uint16    `json:"preference,omitempty"`
	TLSA       *Tlsa     `json:"tlsa,omitempty"`
	CertInfo   *CertInfo `json:"cert_info,omitempty"`
}

// Tlsa struct for SOA information
type Tlsa struct {
	Record       string `json:"record"`
	Certificate  string `json:"certificate"`
	MatchingType uint8  `json:"matchingtype"`
	Selector     uint8  `json:"selector"`
	Usage        uint8  `json:"usage"`
}

// CertInfo struct for certificate information
type CertInfo struct {
	CommonName string `json:"common_name,omitempty"`
	DaneKey    string `json:"dane_key,omitempty"`
}
