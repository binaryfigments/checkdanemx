# checkdanemx
Check DANE / TLSA for MX records

Still some work in progress. It's made for checking the TLSA records for the MX records of a domain. STARTTLS with TLSA records for DANE is is prefered bij the Dutch government https://www.forumstandaardisatie.nl/standaard/starttls-en-dane.

What does this tool do:

* MX records lookups
* TLSA record lookups for DANE
* Get certificate information (Usage 3, DANE-EE only at the moment)
* Compare the certificate (hashes)

Some things to do:

* DNSSEC check, no DANE with no DNSSEC
* ~~Compare certificate with hash~~

## Installation

```
go get -u github.com/binaryfigments/checkdanemx
go install github.com/binaryfigments/checkdanemx
```

## Depends on

* https://github.com/fatih/color
* https://github.com/miekg/dns
* https://golang.org/x/net/idna
* https://golang.org/x/net/publicsuffix

## Running from the command line

```
$ checkdanemx 
Usage of checkdanemx:
  -certs string
    	Get and check the certificates, will not always work with home cable/dsl connections. (default "no")
  -domain string
    	The domain name to test. (Required)
  -nameserver string
    	The nameserver to use. (default "8.8.8.8")
  -output string
    	What output format: json or text. (default "text")
```

## Example usage

```
$ checkdanemx -domain transip.nl -output text

[ MX with DANE/TLSA Check for: transip.nl ]

Domain....: transip.nl
Time......: 2017-05-04 22:58:36.324640552 +0200 CEST
Status....: OK
Message...: Job done!

[ MX and TLSA Records for: transip.nl ]

MX Record..............: relay.transip.nl.
Preference.............: 20
TLSA Record............: _25._tcp.relay.transip.nl
Selector...............: 0
Usage..................: 3
MatchingType...........: 1
Certificate (DNS)......: f0a96869c4fc6d52cf3a4e21c2aaa9af04a288f3c16665825273c9a82e422168
CommonName.............: *.transip.nl
Certificate (Server)...: f0a96869c4fc6d52cf3a4e21c2aaa9af04a288f3c16665825273c9a82e422168
DANE Matching..........: Yes, DANE is OK!

[ MX and TLSA Records for: transip.nl ]

MX Record..............: mail0.transip.nl.
Preference.............: 10
TLSA Record............: NONE
```

## Example usage

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/binaryfigments/checkdanemx/checks"
)

func main() {
	domain := "example.org"
	nameserver := "8.8.8.8"
    certs := "yes" // check the server certs

	check, err := checkdanemx.Run(domain, nameserver, certs)
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
```

## Screenshots

![shot3](https://github.com/binaryfigments/checkdanemx/raw/master/screenshots/shot2.png "shot3")

![shot1](https://github.com/binaryfigments/checkdanemx/raw/master/screenshots/shot1.png "shot1")

![shot2](https://github.com/binaryfigments/checkdanemx/raw/master/screenshots/shot2.png "shot2")