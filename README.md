Olafur Gudmundsson olafur@cloudflare.com 2014/12/01 
Updated 2015/02/16 with better instructions. 
Updated 2015/02/17 with a timeout. (Warren Kumari warren@kumari.net)

A simple program to check which DNSSEC algorithms a particular resolver
validates. 
This program is written in Go and it is the first program I wrote, it
uses go routines to perform the checks in parallel. 
Some resolvers return lots of timeouts when this program runs against
them, just rerun the program with a longer timeout. 

This program requires the package miekg/dns which can be added by issuing 

     "go get github.com/miekg/dns"

__Usage:  
By default this program has an aggressive timeout (5s) to ensure it runs quickly. 
If you get lots of timeouts try rerunning it with a longer timeout.

Command line arguments: ./alg_rep: [-r resolver] [-d] [-v] 

  -d=false: All debug on

  -r="8.8.8.8": address host or host:port of DNS resolver

  -t=5: Timeout.

  -v=false: Short output

  -r selects the resolver to check, 

  Setting the -d option will give lots more output 

  -d should only be used when checking strange results as the output is excessive and 
     only for experts to interpret. 



