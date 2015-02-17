Olafur Gudmudnsson olafur@cloudflare.com 2014/12/01 
Updated 2015/02/16 with better instructions. 

A simple program to check what DNSSEC algorithms a particular resolver
validates. 
This program is written in Go and it is the first program I wrote, it
uses go routines to perform the cheks in parallel. 
Some resolvers return lots of timeouts when this program runs against
them, just rerun the program to and the resolvers give better
results. 

This program requires the package miekg/dns which can be added by issuing 

     "go get github.com/miekg/dns"

USage:  
This program has argressive timeouts to make sure it runs fast. 
If you get lots of timeouts run the program again against the same server to see 
if is slow in validation. 

Command line arguments: ./alg_rep: [-r resolver] [-d] [-v] 

  -d=false: All debug on

  -r="8.8.8.8": address host or host:port of DNS resolver

  -v=false: Short output

  -r selects the resolver to check, 

  Setting the -d option will give lots more output 

  -d should only be used when checking strange results as the output is excessive and 
     only for experts to interpret. 


Sample output: ./alg_rep -r 8.8.4.4  

Zone dnssec-test.org.  Qtype DNSKEY Resolver 8.8.4.4 debug=false verbose=false Prime= V 

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
