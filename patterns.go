package main

import "regexp"

var riskyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)exec\.Command`),
	regexp.MustCompile(`(?i)os\.system`),
	regexp.MustCompile(`(?i)eval\(`),
	regexp.MustCompile(`(?i)password\s*=`),
	regexp.MustCompile(`(?i)secret\s*=`),
	regexp.MustCompile(`http://`),
}
