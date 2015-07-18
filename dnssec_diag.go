/*
 * A program to examine the support for DNSSEC algorithms in resolvers
 *
 * Olafur Gudmundsson CloudFlare Olafur@cloudflare.com    2014/Nov
 *
 * Usage ./alg_rep [-r resolver] [-v] [-d]
 *                  -v verbose
 *                  -d debug
 */
/* Output codes
 *     V  answer verified ==? algorithm supported
 *     -  unverified answer
 *     x  Unspecified algorithm/digest/negative answer combination
 *     T  Timeout
 *     S  ServFail
 *     O  Other
 */
package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

const maxQ = 4

var questions = [maxQ]string{"realy-doesnotexist.dnssec-test.org. A", "alg-8-nsec3.dnssec-test.org. SOA", "alg-13-nsec.dnssec-test.org. SOA", "dnssec-failed.org. SOA"}

// List the define DS digiest alogrithms As of 2014/11
var zone string = "dnssec-test.org." // Our test zone anchors
var debug bool = false
var number = [10]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}

/* This program uses go routines to speed up lookups
 *  we do 80 lookups alg(10) * ds(4) * Nsec-types(2)
 * The program accepts inputs
 */
func main() {
	// Get commandline arguments
	resolver := flag.String("r", "8.8.8.8", "address host or host:port of DNS resolver")
	//	deb := flag.Bool("d", false, "All debug on")
	verbose := flag.Bool("v", false, "Short output")
	//	verbose := false
	flag.Parse()
	// Extract supplied parameters
	//	debug = *deb
	myRes := *resolver
	if myRes[0:1] != "[" {
		myRes = "[" + myRes + "]"
	}
	grade := grade_resolver(myRes, *verbose)
	fmt.Println("Grade: ", grade)
}

func grade_resolver(myRes string, verbose bool) int {
	grade := 0
	// this also does priming query to get dnssec-test.org into cache and check if
	// resolver valiates (no need to query if not validating)
	fmt.Printf("Grading Resolver %s\n", myRes)
	alg8, a8a := ask(questions[1], myRes, verbose)
	if alg8 == " A " {
		grade++
		if a8a {
			grade++
		}
	} else {
		fmt.Println("Bad Alg8 ", alg8, a8a, questions[1])
	}
	//	fmt.Printf("Alg8 %d\n", grade);
	prime, pA := ask(questions[0], myRes, verbose)
	if prime == " x " {
		grade++
		if pA {
			grade++
		}
	} else {
		fmt.Println("Lie  ", alg8, a8a, questions[0])
	}

	//	fmt.Printf("Lie8 %d\n", grade);
	alg13, a13a := ask(questions[2], myRes, verbose)
	if alg13 == " A " {
		grade++
		if a13a {
			grade++
		}
	} else {
		fmt.Println("Bad Alg13 ", alg13, a13a, questions[2])
	}

	//	fmt.Printf("Alg13 %d\n", grade);
	failure := " O "
	fa := false
	if a8a || a13a {
		failure, fa = ask(questions[3], myRes, verbose)
		if failure == " S " {
			grade++
			if fa {
				fmt.Println("BAD BAD ", failure, fa, questions[3])
			} else {
				grade++
			}
		} else if failure == " A " {
			fmt.Println("Unexpected AnswerD ", failure, fa, questions[3])
		} else {
			fmt.Println("Bad Invalid DNSSEC ", failure, fa, questions[3])
		}
		fmt.Printf("DNSSEC validation == YES\n")
	} else {
		fmt.Printf("DNSSEC validation == NO\n")
	}
	if verbose {
		fmt.Println("Results: ", grade, prime, pA, alg8, a8a, alg13, a13a, failure, fa)
	}
	return grade
}

func supports(name string, myType uint16, resolver string, verb bool) (string, bool) {
	supp, ad, msg := validate_name(name, myType, resolver, debug)
	if debug || verb {
		fmt.Printf("X %v %v %s\n", debug, verb, msg)
	}
	return supp, ad
}

/*
 * prints all the RR's in the array/a section
 */
func PrintSection(prefix string, z []dns.RR, display bool) {
	if display {
		fmt.Printf("%s\n", prefix)
		for a := range z {
			fmt.Printf("%s\n", z[a].String())
		}
	}
}

func doLookup(qn string, qt uint16, resolver string) (*dns.Msg, bool) {
	c := dns.Client{}
	m := &dns.Msg{}
	m.SetEdns0(2048, true) // asking for DO bit  // create a fallback XXX
	m.SetQuestion(qn, qt)
	// need to set a longer timerout

	msg, _, err := c.Exchange(m, resolver+":53")
	if err != nil { // most likely timeout retry
		msg, _, err = c.Exchange(m, resolver+":53")
		if err != nil {
			fmt.Printf("Lookup Error %s %v\n", qn, err)
			return msg, true
		}
	}
	return msg, false
}

/*
 * A function to ask a question and returns if the answer existed and if it was validated
 * Input is the name and query type, what resolver to use and if debugging is turned on
 * return codes:
 *  " T " == Timeout
 *  " - " ==
 *  " V " == Validted
 *  " + " == Empty answer
 *  " x " == NXDOMAIN
 *  " S " == Servfail
 *  " F " == Other error
 */
func validate_name(qn string, qt uint16, resolver string, debug bool) (supp string, ad bool, msg string) {
	name, timeout := doLookup(qn, qt, resolver)
	if timeout {
		return " T ", false, "Lookup Errorr"
	}
	supp = " - "
	counts := number[len(name.Answer)] + " " + number[len(name.Ns)] + " " + number[len(name.Extra)]
	ad = name.AuthenticatedData
	switch {
	case name.Rcode == dns.RcodeSuccess && len(name.Answer) > 0:
		// got an actual answer
		PrintSection("ANSWER", name.Answer, debug)
		supp = " A " // Answer
	case name.Rcode == dns.RcodeSuccess:
		// Got empty answer expect stuff in Authority
		PrintSection("Empty answer "+counts, name.Ns, debug)
		supp = " + "
	case name.Rcode == dns.RcodeNameError:
		// No name exepect stuff in Authority
		PrintSection("DoesNotExist "+counts, name.Ns, debug)
		supp = " x "
	case name.Rcode == dns.RcodeServerFailure:
		if debug { // lookup failed
			fmt.Printf("ServFail, %s %s\n", qn, counts)
		}
		supp = " S "
	default:
		// bad case
		fmt.Printf("unexpected %s rcode= %d %s\n", qn, counts)
		fmt.Printf(name.String())
		supp = " F "
	}
	return
}

func ask(question string, myRes string, deb bool) (string, bool) {
	arr := strings.Split(question, " ")
	qtype := dns.TypeA
	switch arr[1] {
	case "SOA":
		qtype = dns.TypeSOA
	case "TXT":
		qtype = dns.TypeTXT
	case "AAAA":
		qtype = dns.TypeAAAA
	}
	return supports(arr[0], qtype, myRes, deb)
}
