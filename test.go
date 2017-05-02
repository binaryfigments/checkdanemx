package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/binaryfigments/checkdanemx/checks"
)

func mainq() {
	domain := "example.org"
	nameserver := "8.8.8.8"

	check, err := checkdanemx.Run(domain, nameserver)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	json, err := json.MarshalIndent(check, "", "   ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", json)
	os.Exit(0)
}
