##### Bazga Mihai-Carol

## Task 1
##### Heuristic 1
Some malicious URLs have been flagged from the database.

##### Heuristic 2
Some extensions and URL patterns could contain malware: `.exe`, `/exe/`,
`.css`, `pdf` etc.
Other extensions and patterns can be found in file `/patterns/extensions`[^3].

##### Heuristic 3
URLs that contain IP addresses and ports are suspicious.

##### Heuristic 4[^1][^2]
Some exotic or non-existent TLDs are used for phishing websites because they
are cheap (e.g.: `.cc`, `.pw`, `.ga`). They could be found in the file
`/patterns/tlds`[^3].

##### Heuristic 5
Phishers target popular companies such as PayPal, Google, Facebook
and marketplaces. To do so, they try to obfuscate the URL by adding a lot of
subdomains, dots, hyphens and slashes. Some of these patterns can be found
in the file `/patterns/phishing`[^3].

The phishers try to trick web users by mimicking the doubtful URL look
legitimate.

##### Heuristic 6
Suspicious URLs have more than five digits.

##### Heuristic 7[^1]
Suspicious URLs have more than three hypens.

##### Heuristic 8[^1]
Suspicious URLs have more than four dots.

##### Heuristic 9
Suspicious URLs does not end with '/' after hostname.

##### Heuristic 10
URLs with malformed `www` (e.g `www-i2`) could be related to phishing websites.

##### Heuristic 11
Information such as session ids and email should be never in the URL.

##### Heuristic 12
Some websites such as google.com, bing.com are known to be safe, so we can
simply flag them as benign.
Also, after a quick check, we can observe that torrent sharing websites are
generally safe,despite the fact that the torrent's content may contain malware.
These sites and patterns can be found in the file `/patterns/whitelist`[^3].


## Task 2
Bruteforce attacks, as mentioned in the homework statament, have a
`flow_duration` of approximately 1 second and `flow_pkts_payload.avg` other
than 0. Taking this into consideration, some benign traffic will be flagged as
malicious. Most of these attacks usually have `bwd_pkts_tot` equals 63-64.
In spite of that, there are some bruteforce attacks with  lower values.
Sticking to 40 is a safe way to find most of them.

Regarding cryptominer traffic, there are 2 ways it can operate.
One would be when `flow_duration` is nearly 0 and `flow_pkts_payload.avg` is
one of the following value: 40, 201 or 220.5.
The second would be when the `flow_duration` is longer than 1 second and the
`flow_pkts_payload.avg` equals 50.
In the case that origin IP is 255.255.255.255, the traffic won't be flagged
as cryptominer. 

[^1]: Heuristic referenced from study [Intelligent phishing url detection using
association rule mining](https://hcis-journal.springeropen.com/articles/10.1186/s13673-016-0064-3)

[^2]: Suspicious TLDs referenced from article [A Peek into Top-Level Domains
and Cybercrime](https://unit42.paloaltonetworks.com/top-level-domains-cybercrime/)

[^3]: File mentioned contains regex expressions on each line.
