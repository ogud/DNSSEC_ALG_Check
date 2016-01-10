Olafur Gudmundsson olafur@cloudflare.com 2014/12/01 

Updated 2015/02/17 with better timeout and retry selector. (Warren Kumari warren@kumari.net)
Updated 2015/04/01 with better instructions. 

A simple program to check which DNSSEC algorithms a particular resolver
validates.  This program is written in Go and it is the first real program I
wrote using go routines.  It uses the go routines to perform the checks in
parallel.  Some resolvers return lots of timeouts when this program runs against
them, just wait few seconds and then rerun the program for better results.

**Note:** IF this is the FIRST time you use the go language you need to

  1. download and install go first here for instructions https://golang.org/doc/install
  2. need to set a GOPATH variable in your environment, see https://golang.org/doc/code.html#GOPATH

This program requires the package `miekg/dns` which can be added by issuing 

    go get github.com/miekg/dns

and build the program by issuing

    go build alg_rep.go


Command line arguments: `./alg_rep: [-r resolver] [-z zone] [-d] [-v]`

    -d=false: All debug on
    -r="8.8.8.8": Address host or host:port of DNS resolver
    -v=false: Short output
    -z="dnssec-test.org.": Domain to use for checking


`-d` should only be used when checking strange results as the output is excessive and 
     only for experts to interpret. 

**Note:** the program has short timeouts due to the large number of queries asked
If there are many timeout's re-running the program will most of the time get answers without timeouts.

Sample output: `./alg_rep -r 8.8.4.4`

    Zone dnssec-test.org.  Qtype DNSKEY Resolver [8.8.4.4] debug=false verbose=false
    Prime= V 
    DS     :  1  2  3  4  |  1  2  3  4
    ALGS   :    NSEC      |     NSEC3
    alg-1  :  S  S  S  S  |  x  x  x  x  => RSA-MD5 OBSOLETE
    alg-3  :  -  -  -  -  |  x  x  x  x  => DSA/SHA1
    alg-5  :  V  V  -  V  |  x  x  x  x  => RSA/SHA1
    alg-6  :  x  x  x  x  |  -  -  -  -  => DSA-NSEC3-SHA1
    alg-7  :  x  x  x  x  |  V  V  -  V  => RSA-NSEC3-SHA1
    alg-8  :  V  V  -  V  |  V  V  -  V  => RSA-SHA256
    alg-10 :  V  V  -  V  |  V  V  -  V  => RSA-SHA512
    alg-12 :  -  -  -  -  |  -  -  -  -  => GOST-ECC
    alg-13 :  V  V  -  V  |  V  V  -  V  => ECDSAP256SHA256
    alg-14 :  V  V  -  V  |  V  V  -  V  => ECDSAP384SHA384
    V == Validates  - == Answer  x == Alg Not specified
    T == Timeout S == ServFail O == Other Error
    DS algs 1=SHA1 2=SHA2-256 3=GOST 4=SHA2-384
