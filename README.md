Olafur Gudmudnsson olafur@cloudflare.com 2014/12/01 
A simple program to check what DNSSEC algorithms a particular resolver
validates. 
This program is written in Go and it is the first program I wrote, it
uses go routines to perform the cheks in parallel. 
Some resolvers return lots of timeouts when this program runs against
them, just rerun the program to and the resolvers give better
results. 

This program requires the package miekg/dns which is available from ??
TODO 
USage: 
TODO 
