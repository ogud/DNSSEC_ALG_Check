Olafur Gudmundsson olafur@cloudflare.com 2014/12/01 

Updated 2015/02/17 with better timeout and retry selector. (Warren Kumari warren@kumari.net)
Updated 2015/04/01 with better instructions. 

A simple program to check which DNSSEC algorithms a particular resolver
validates. 
This program is written in Go and it is the first real program I wrote using go routines. 
It uses the go routines to perform the checks in parallel. 
Some resolvers return lots of timeouts when this program runs against
them, just wait few seconds and then rerun the program for better results. 

Note: IF this is the FIRST time you use the go language you need to 
  a) download and install go first here for instructions https://golang.org/doc/install
  b) need to set a GOPATH variable in your environment, see https://golang.org/doc/code.html#GOPATH

This program requires the package miekg/dns which can be added by issuing 

     "go get github.com/miekg/dns"

and build the program by issuing
     "go build alg_rep.go" 

By this program has an aggressive timeout (.5s) to ensure it runs quickly. 

Command line arguments: ./alg_rep: [-r resolver] [-d] [-v] 
```
  -d=false: All debug on

  -r="8.8.8.8": address host or host:port of the DNS resolver to use 

  -v=false: Short output

  Setting the -d option will give lots more output 

  `-d` should only be used when checking strange results as the output is excessive and 
     only for experts to interpret. 
```

Note: the program has short timeouts due to the large number of queries asked
If there are many timeout's re-running the program will most of the time get answers without timeouts. 

Sample output: ./alg_rep -r 8.8.4.4  
```
Zone dnssec-test.org.  Qtype DNSKEY Resolver 8.8.8.8 debug=false verbose=false Prime= V
DS     :  1  2  3  4  |  1  2  3  4
ALGS   :    NSEC      |     NSEC3
alg-1  :  S  S  S  S  |  x  x  x  x  => RSAMD5
alg-3  :  -  -  -  -  |  x  x  x  x  => DSA
alg-5  :  V  V  -  V  |  x  x  x  x  => RSASHA1
alg-6  :  x  x  x  x  |  -  -  -  -  => DSA-NSEC3-SHA1
alg-7  :  x  x  x  x  |  V  V  -  V  => RSASHA1-NSEC3
alg-8  :  V  V  -  V  |  V  V  -  V  => RSASHA-256
alg-10 :  V  V  -  V  |  V  V  -  V  => RSASHA-512
alg-12 :  -  -  -  -  |  -  -  -  -  => ECC-GOST
alg-13 :  V  V  -  V  |  V  V  -  V  => ECSDAP256-SHA256
alg-14 :  V  V  -  V  |  V  V  -  V  => ECSDAP384-SHA384
V == Validates  - == Answer  x == Alg Not specified
T == Timeout S == ServFail O == Other Error
DS algs 1=SHA1 2=SHA2-256 3=GOST 4=SHA2-384
```
