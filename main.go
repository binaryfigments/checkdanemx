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
	checkOutput := flag.String("output", "json", "What output format: json or text.")
	flag.Parse()
	if *checkHost == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	check, err := checkdanemx.Run(*checkHost, *checkNameserver)
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
		fmt.Printf("Domain....: %v\n", check.Question.JobDomain)
		fmt.Printf("Time......: %v\n", check.Question.JobTime)
		fmt.Printf("Status....: %v\n", check.Question.JobStatus)
		fmt.Printf("Message...: %v\n", check.Question.JobMessage)
		for _, mx := range check.Answer.MxRecords {
			fmt.Println("")
			color.Cyan("[ MX and TLSA Records for: %s ]", check.Question.JobDomain)
			fmt.Printf("MX Record......: %v\n", mx.Mx)
			fmt.Printf("Preference.....: %v\n", mx.Preference)
			if mx.TLSA.Certificate == "" {
				color.Red("TLSA Record....: %s", "NONE")
			} else {
				color.Green("TLSA Record....: %s", mx.TLSA.Record)
				fmt.Printf("Selector.......: %v\n", mx.TLSA.Selector)
				fmt.Printf("Usage..........: %v\n", mx.TLSA.Usage)
				fmt.Printf("MatchingType...: %v\n", mx.TLSA.MatchingType)
				fmt.Printf("Certificate....: %v\n", mx.TLSA.Certificate)
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
