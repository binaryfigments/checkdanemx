package checkdata

import "time"

// Message struct for returning the question and the answer.
type Message struct {
	Question Question `json:"question"`
	Answer   Answer   `json:"answer"`
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
	Mx         string `json:"mx,omitempty"`
	Preference uint16 `json:"preference,omitempty"`
	TLSA       *Tlsa  `json:"tlsa,omitempty"`
}

// Tlsa struct for SOA information
type Tlsa struct {
	Record       string `json:"record,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	MatchingType uint8  `json:"matchingtype,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	Usage        uint8  `json:"usage,omitempty"`
}
