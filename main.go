package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/binaryfigments/checkdanemx/checks"
	"github.com/fatih/color"
)

func main() {
	checkHost := flag.String("domain", "", "The domain name to test. (Required)")
	checkNameserver := flag.String("nameserver", "8.8.8.8", "The nameserver to use.")
	checkOutput := flag.String("output", "text", "What output format: json or text.")
	checkCerts := flag.String("certs", "no", "Get and check the certificates, will not always work with home cable/dsl connections.")
	flag.Parse()
	if *checkHost == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	check, err := checkdanemx.Run(*checkHost, *checkNameserver, *checkCerts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	switch *checkOutput {
	case "json":
		json, err := json.MarshalIndent(check, "", "   ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", json)
	case "text":
		fmt.Println("")
		color.Cyan("[ MX with DANE/TLSA Check for: %s ]", check.Question.JobDomain)
		fmt.Println("")
		fmt.Printf("Domain....: %v\n", check.Question.JobDomain)
		fmt.Printf("Time......: %v\n", check.Question.JobTime)
		fmt.Printf("Status....: %v\n", check.Question.JobStatus)
		fmt.Printf("Message...: %v\n", check.Question.JobMessage)
		for _, mx := range check.Answer.MxRecords {
			fmt.Println("")
			color.Cyan("[ MX and TLSA Records for: %s ]", mx.Mx)
			fmt.Println("")
			fmt.Printf("MX Record..............: %v\n", mx.Mx)
			fmt.Printf("Preference.............: %v\n", mx.Preference)
			fmt.Println("")
			for _, tlsa := range mx.TLSA {
				if tlsa.Certificate == "" {
					color.Red("TLSA Records...........: %s", "NONE")
				} else {
					color.Green("TLSA Records...........: %s", tlsa.Record)
					fmt.Printf("Content................: %v %v %v %v\n", tlsa.Usage, tlsa.Selector, tlsa.MatchingType, tlsa.Certificate)
					if *checkCerts == "yes" {
						color.Cyan("CommonName.............: %s", tlsa.ServerCertificate.CommonName)
						fmt.Printf("Certificate (Server)...: %v\n", tlsa.ServerCertificate.Certificate)
						if tlsa.Certificate == tlsa.ServerCertificate.Certificate {
							color.Green("DANE Matching..........: %s", "Yes, DANE is OK!")
						} else {
							color.Red("DANE Matching..........: %s", "No, DANE Fails!")
						}
					}
					fmt.Println("")
				}
			}
		}
		fmt.Println("")
	default:
		err := errors.New("Output format is not json or text.")
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(0)
}
