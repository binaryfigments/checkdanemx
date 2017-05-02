# checkdanemx
Check DANE / TLSA for MX records

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
  -domain string
    	The domain name to test. (Required)
  -nameserver string
    	The nameserver to use. (default "8.8.8.8")
  -output string
    	What output format: json or text. (default "json")
```

## Example usage

```
$ checkdanemx -domain transip.nl -output text

[ MX with DANE/TLSA Check for: transip.nl ]
Domain....: transip.nl
Time......: 2017-05-03 01:36:38.365597748 +0200 CEST
Status....: OK
Message...: Job done!

[ MX and TLSA Records for: transip.nl ]
MX Record......: mail0.transip.nl.
Preference.....: 10
TLSA Record....: NONE

[ MX and TLSA Records for: transip.nl ]
MX Record......: relay.transip.nl.
Preference.....: 20
TLSA Record....: _25._tcp.relay.transip.nl
Selector.......: 0
Usage..........: 3
MatchingType...: 1
Certificate....: f0a96869c4fc6d52cf3a4e21c2aaa9af04a288f3c16665825273c9a82e422168
```

## Screenshots

[shot1]: https://github.com/binaryfigments/checkdanemx/raw/master/screenshots/shot1.png "Shot1"

[shot2]: https://github.com/binaryfigments/checkdanemx/raw/master/screenshots/shot2.png "Shot2"
