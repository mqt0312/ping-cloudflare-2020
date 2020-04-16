
# ping.c - A 24-hrs implementation of Linux's ping for Cloudflare 2020 Internship
By: Minh Quang Truong - mqt0312[@]gmail[.]com

## 1. Compile

Compile ping.c with: gcc -o ping ping.c
Alternatively, run make with the provided Makefile

## 2. Run

ping takes in a hostname or an IPv4 address and two optional arguments:
  -t=TTL: Set TTL to a specific value
  -n=PACKET_LIMIT: Send only PACKET_LIMIT ping packet. If not specified, ping will send until termination.

You can terminate ping with CTRL-C or send SIGINT to the process. The report will be printed upon termination

## 3. Example:

Pinging google[.]com normally

    $ ./ping google.com
    Pinging google.com (172.217.6.206) 84 bytes
    64 bytes from lga25s54-in-f14.1e100.net (172.217.6.206): TTL=64, MAX_PKT=0 seq=1, checksum=68c3, time=102.8ms
    64 bytes from lga25s54-in-f14.1e100.net (172.217.6.206): TTL=64, MAX_PKT=0 seq=2, checksum=67c3, time=39.60ms
    64 bytes from lga25s54-in-f14.1e100.net (172.217.6.206): TTL=64, MAX_PKT=0 seq=3, checksum=66c3, time=64.89ms
    64 bytes from lga25s54-in-f14.1e100.net (172.217.6.206): TTL=64, MAX_PKT=0 seq=4, checksum=65c3, time=68.31ms
    64 bytes from lga25s54-in-f14.1e100.net (172.217.6.206): TTL=64, MAX_PKT=0 seq=5, checksum=64c3, time=125.8ms
    ^C
    ------- Stat for google.com -------
      Total no. of packet: 5     
        Success: 5     
        Lost: 0     
        Success Rate: 100.0%
      Total time: 4870.14ms
      Min time: 39.60ms
      Max time: 125.8ms
      Avg time: 80.29ms
      Stddev: 30.39

Pinging Cloudflare with TTL=32 and sending only 10 packet

    $ ./ping cloudflare.com -t 32 -n 10
    [WARNING] dns_resolve_r: Cannot resolve reversed lookup of hostname.
    Pinging cloudflare.com (104.17.175.85) 84 bytes
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=1, checksum=67c3, time=101.2ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=2, checksum=66c3, time=31.90ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=3, checksum=65c3, time=118.0ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=4, checksum=64c3, time=126.4ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=5, checksum=63c3, time=130.7ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=6, checksum=62c3, time=122.7ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=7, checksum=61c3, time=17.06ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=8, checksum=60c3, time=131.5ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=9, checksum=5fc3, time=103.5ms
    64 bytes from  (104.17.175.85): TTL=32, MAX_PKT=10 seq=10, checksum=5ec3, time=46.39ms
    
    ------- Stat for cloudflare.com -------
      Total no. of packet: 10    
        Success: 10    
        Lost: 0     
        Success Rate: 100.0%
      Total time: 10932.3ms
      Min time: 17.06ms
      Max time: 131.5ms
      Avg time: 92.96ms
      Stddev: 41.70

