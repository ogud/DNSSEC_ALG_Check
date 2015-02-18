/*
 * A program to examine the support for DNSSEC algorithms in resolvers
 *
 * Olafur Gudmundsson CloudFlare Olafur@cloudflare.com    2014/Nov
 *   Updated 2015/Feb
 *
 * Usage ./alg_rep [-r resolver] [-v] [-d]
 *                  -v verbose
 *                  -d debug
 */
/* Output codes for each question
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
	"time"
	"os"
)

// change the array sizes below when new algorithms are added
// When new algorithms are added the function print_table() needs updating
// List the defined signature algorithms as of 2014/11
// 2 4 9 11 skipped as not valid algs 14 is max

const maxAlg = 10
const maxDs = 4
const zone string = "dnssec-test.org."     // Our test zone anchors

var algs = [maxAlg]string{"alg-1", "alg-3", "alg-5", "alg-6", "alg-7", "alg-8",
	"alg-10", "alg-12", "alg-13", "alg-14"}
var names = [maxAlg]string{"RSAMD5", "DSA", "RSASHA1", "DSA-NSEC3-SHA1",
	"RSASHA1-NSEC3",
	"RSASHA-256", "RSASHA-512", "ECC-GOST", "ECSDAP256-SHA256", "ECSDAP384-SHA384"}

// List the define DS digiest alogrithms As of 2014/11
var ds = [maxDs]string{"ds-1", "ds-2", "ds-3", "ds-4"}

var number = [10]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
var result [maxAlg][maxDs + maxDs]string // Results are stored in here

// Operating controls 
var debug bool = false
var maxRetry int = 3

// Work sets up one go-routine for each Digest algorithm
func work(d int, myType uint16, resolver string, verb bool, done chan bool) {
	// Scan the digest algorithms for both NSEC and NSEC3 zones
	for a := range algs {
		name := ds[d] + "." + algs[a] + "-nsec"
		result[a][d] = supports(name+"."+zone, myType, resolver, verb)
		result[a][d+maxDs] = supports(name+"3."+zone, myType, resolver, verb)
	}
	done <- true // report completion
}

/* This program uses go routines to speed up lookups
 *  we do 80 lookups alg(10) * ds(4) * Nsec-types(2)
 * The program accepts inputs
 */
func main() {
	// Get commandline arguments
	resolver := flag.String("r", "8.8.8.8", "address host or host:port of DNS resolver")
	deb := flag.Bool("d", false, "All debug on")
	verbose := flag.Bool("v", false, "Short output")
	retry := flag.Int("t", 3, "How many times to retry each query")
	flag.Parse()
	// Extract supplied parameters
	myType := uint16(48) // DNSKEY (as single key signed zone this is suffiicent test
	debug = *deb
	myRes := *resolver
	maxRetry = *retry

	// first do a priming query to get dnssec-test.org into cache and check if
	// resolver valiates ==> no need to continue if resolver is not validating
	prime := supports(zone, myType, myRes, true)
	if prime == " T " {
		fmt.Printf("Not a resolver ???  %s\n", myRes)
		os.Exit(1)
	}

	fmt.Printf("Zone %s  Qtype DNSKEY Resolver %s debug=%v verbose=%v Prime=%v\n", zone,
		myRes, debug, *verbose, prime)
	if prime == " V " { // priming we can check all algorithms
		// create the channel we work on
		done := make(chan bool)
		alive := 0 // how many routines are still running
		// ask for DS-x in parallel
		for i := range ds {
			go work(i, myType, myRes, debug, done)
			alive++
		}
		for alive > 0 { // wait for lookups to finish
			if <-done {
				alive--
			}
		}
		print_table()
	} else {
		fmt.Printf("Resolver " + myRes + " is not validating\n")
	}
}

// function to create a line in report fo support by that algrithm
func list_supp(supp [maxDs + maxDs]string) (out string) {
	for d := range supp {
		if d == maxDs { // separator between NSEC and NSEC3 in table
			out += " | "
		}
		out += supp[d]
	}
	return out
}

func supports(name string, myType uint16, resolver string, verb bool) string {
	supp, msg := validate_name(name, myType, resolver, debug)
	if debug || verb {
		fmt.Printf("%s\n", msg)
	}
	return supp
}

func print_table() {
	// Print table of Results
	fmt.Printf("DS     :  1  2  3  4  |  1  2  3  4\n" +
		"ALGS   :    NSEC      |     NSEC3\n")
	for a := range algs {
		msg := algs[a]
		if len(msg) < 6 {
			msg += " "
		}
		fmt.Printf("%s\n", msg+" : "+list_supp(result[a])+" => "+
			names[a])
	}
	fmt.Printf("V == Validates  - == Answer  x == Alg Not specified\n" +
		"T == Timeout S == ServFail O == Other Error\n" +
		"DS algs 1=SHA1 2=SHA2-256 3=GOST 4=SHA2-384\n")
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

// function to perform the lookup and retries
// returns the message and a flag if there was a timeout
//
func doLookup(qn string, qt uint16, resolver string) (*dns.Msg, bool) {
	var myerr error
	c := dns.Client{}
	c.ReadTimeout = time.Duration(1) * time.Second
	m := &dns.Msg{}
	m.SetEdns0(2048, true) // asking for DO bit  // create a fallback XXX
	m.SetQuestion(qn, qt)
	// need to set a longer timerout

	for i := 0; i <= maxRetry; i++ {
		msg, _, err := c.Exchange(m, resolver+":53")
		if err == nil {
			return msg, false
		}
		myerr = err
	}
	fmt.Printf("Lookup Error %d %s %v\n", qn, myerr)
	return nil, true
}

/*
 * A function to ask a question and returns if the answer existed and if it was validated
 * Input is the name and query type, what resolver to use and if debugging is turned on
 */
func validate_name(qn string, qt uint16, resolver string, debug bool) (supp string,
	msg string) {

	name, timeout := doLookup(qn, qt, resolver)
	if timeout {
		return " T ", "Lookup Error"
	}
	supp = " - "
	counts := number[len(name.Answer)] + " " + number[len(name.Ns)] + " " +
		number[len(name.Extra)]
	switch {
	case name.Rcode == dns.RcodeSuccess && len(name.Answer) > 0:
		// got an actual answer
		PrintSection("ANSWER", name.Answer, debug)
		if name.AuthenticatedData { // AD bit set
			supp = " V "
		}
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
