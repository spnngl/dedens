# Comprehensive List of DNS RFCs

The Domain Name System (DNS) has evolved over decades through the Internet Engineering Task Force (IETF). While there are hundreds of RFCs touching on DNS, they can be broadly separated into the principal modern standards and the historical, operational, or niche extensions.

Plain-text copies of every RFC below are in [`archive/`](archive/); `just rfc-archive` downloads them again after this list changes.

---

## Part 1: Principal DNS RFCs (Modern Core)

These are the foundational RFCs required for modern DNS implementation, including core architecture, security, transport, and major features.

### Core Architecture & Implementation
* **[RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034):** Domain Names - Concepts and Facilities (The core architecture)
* **[RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035):** Domain Names - Implementation and Specification (The core technical spec)
* **[RFC 1123](https://datatracker.ietf.org/doc/html/rfc1123):** Requirements for Internet Hosts - Application and Support (Section 6.1: DNS)
* **[RFC 1982](https://datatracker.ietf.org/doc/html/rfc1982):** Serial Number Arithmetic (SOA serial comparison)
* **[RFC 1995](https://datatracker.ietf.org/doc/html/rfc1995):** Incremental Zone Transfer in DNS (IXFR)
* **[RFC 1996](https://datatracker.ietf.org/doc/html/rfc1996):** A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
* **[RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136):** Dynamic Updates in the Domain Name System (DNS UPDATE)
* **[RFC 2181](https://datatracker.ietf.org/doc/html/rfc2181):** Clarifications to the DNS Specification
* **[RFC 2308](https://datatracker.ietf.org/doc/html/rfc2308):** Negative Caching of DNS Queries (Ncache)
* **[RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782):** A DNS RR for specifying the location of services (SRV)
* **[RFC 3152](https://datatracker.ietf.org/doc/html/rfc3152):** Delegation of IP6.ARPA (reverse lookup of IPv6 addresses)
* **[RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596):** DNS Extensions to Support IP Version 6 (AAAA records)
* **[RFC 3597](https://datatracker.ietf.org/doc/html/rfc3597):** Handling of Unknown DNS Resource Record (RR) Types
* **[RFC 4343](https://datatracker.ietf.org/doc/html/rfc4343):** Domain Name System (DNS) Case Insensitivity Clarification
* **[RFC 4592](https://datatracker.ietf.org/doc/html/rfc4592):** The Role of Wildcards in the Domain Name System
* **[RFC 5452](https://datatracker.ietf.org/doc/html/rfc5452):** Measures for Making DNS More Resilient against Forged Answers
* **[RFC 5936](https://datatracker.ietf.org/doc/html/rfc5936):** DNS Zone Transfer Protocol (AXFR)
* **[RFC 6604](https://datatracker.ietf.org/doc/html/rfc6604):** xNAME RCODE and Status Bits Clarification
* **[RFC 6672](https://datatracker.ietf.org/doc/html/rfc6672):** DNAME Redirection in the DNS
* **[RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891):** Extension Mechanisms for DNS (EDNS0)
* **[RFC 7766](https://datatracker.ietf.org/doc/html/rfc7766):** DNS Transport over TCP - Implementation Requirements
* **[RFC 7873](https://datatracker.ietf.org/doc/html/rfc7873):** Domain Name System (DNS) Cookies
* **[RFC 8109](https://datatracker.ietf.org/doc/html/rfc8109):** Initializing a DNS Resolver with Priming Queries
* **[RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482):** Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY
* **[RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914):** Extended DNS Errors
* **[RFC 8945](https://datatracker.ietf.org/doc/html/rfc8945):** Secret Key Transaction Authentication for DNS (TSIG)
* **[RFC 9018](https://datatracker.ietf.org/doc/html/rfc9018):** Interoperable Domain Name System (DNS) Server Cookies
* **[RFC 9460](https://datatracker.ietf.org/doc/html/rfc9460):** Service Binding and Parameter Specification via the DNS (SVCB and HTTPS RRs)
* **[RFC 9471](https://datatracker.ietf.org/doc/html/rfc9471):** DNS Glue Requirements in Referral Responses
* **[RFC 9499](https://datatracker.ietf.org/doc/html/rfc9499):** DNS Terminology (Obsoletes RFC 8499)
* **[RFC 9520](https://datatracker.ietf.org/doc/html/rfc9520):** Negative Caching of DNS Resolution Failures
* **[RFC 9619](https://datatracker.ietf.org/doc/html/rfc9619):** In the DNS, QDCOUNT Is (Usually) One

### DNSSEC (DNS Security Extensions)
* **[RFC 3225](https://datatracker.ietf.org/doc/html/rfc3225):** Indicating Resolver Support of DNSSEC (DO bit)
* **[RFC 4033](https://datatracker.ietf.org/doc/html/rfc4033):** DNS Security Introduction and Requirements
* **[RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034):** Resource Records for the DNS Security Extensions
* **[RFC 4035](https://datatracker.ietf.org/doc/html/rfc4035):** Protocol Modifications for the DNS Security Extensions
* **[RFC 4509](https://datatracker.ietf.org/doc/html/rfc4509):** Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records
* **[RFC 5011](https://datatracker.ietf.org/doc/html/rfc5011):** Automated Updates of DNSSEC Trust Anchors
* **[RFC 5155](https://datatracker.ietf.org/doc/html/rfc5155):** DNSSEC Hashed Authenticated Denial of Existence (NSEC3)
* **[RFC 5702](https://datatracker.ietf.org/doc/html/rfc5702):** Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
* **[RFC 6605](https://datatracker.ietf.org/doc/html/rfc6605):** Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
* **[RFC 6840](https://datatracker.ietf.org/doc/html/rfc6840):** Clarifications and Implementation Notes for DNSSEC
* **[RFC 7646](https://datatracker.ietf.org/doc/html/rfc7646):** Definition and Use of DNSSEC Negative Trust Anchors
* **[RFC 8080](https://datatracker.ietf.org/doc/html/rfc8080):** Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC
* **[RFC 8198](https://datatracker.ietf.org/doc/html/rfc8198):** Aggressive Use of DNSSEC-Validated Cache
* **[RFC 9077](https://datatracker.ietf.org/doc/html/rfc9077):** NSEC and NSEC3: TTLs and Aggressive Use
* **[RFC 9276](https://datatracker.ietf.org/doc/html/rfc9276):** Guidance for NSEC3 Parameter Settings
* **[RFC 9364](https://datatracker.ietf.org/doc/html/rfc9364):** DNS Security Extensions (DNSSEC) (BCP 237, overview of the DNSSEC document set)
* **[RFC 9718](https://datatracker.ietf.org/doc/html/rfc9718):** DNSSEC Trust Anchor Publication for the Root Zone (Obsoletes RFC 7958)
* **[RFC 9824](https://datatracker.ietf.org/doc/html/rfc9824):** Compact Denial of Existence in DNSSEC
* **[RFC 9904](https://datatracker.ietf.org/doc/html/rfc9904):** DNSSEC Cryptographic Algorithm Recommendation Update Process (Obsoletes RFC 8624)
* **[RFC 9905](https://datatracker.ietf.org/doc/html/rfc9905):** Deprecating the Use of SHA-1 in DNSSEC Signature Algorithms

### Encrypted Transport & Privacy
* **[RFC 7252](https://datatracker.ietf.org/doc/html/rfc7252):** The Constrained Application Protocol (CoAP), the carrier of DoC
* **[RFC 7641](https://datatracker.ietf.org/doc/html/rfc7641):** Observing Resources in CoAP (for the record: DoC does not use it)
* **[RFC 7830](https://datatracker.ietf.org/doc/html/rfc7830):** The EDNS(0) Padding Option
* **[RFC 7858](https://datatracker.ietf.org/doc/html/rfc7858):** Specification for DNS over Transport Layer Security (DoT)
* **[RFC 7959](https://datatracker.ietf.org/doc/html/rfc7959):** Block-Wise Transfers in CoAP
* **[RFC 8132](https://datatracker.ietf.org/doc/html/rfc8132):** PATCH and FETCH Methods for the Constrained Application Protocol (CoAP)
* **[RFC 8310](https://datatracker.ietf.org/doc/html/rfc8310):** Usage Profiles for DNS over TLS and DNS over DTLS
* **[RFC 8467](https://datatracker.ietf.org/doc/html/rfc8467):** Padding Policies for Extension Mechanisms for DNS (EDNS(0))
* **[RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484):** DNS Queries over HTTPS (DoH)
* **[RFC 8613](https://datatracker.ietf.org/doc/html/rfc8613):** Object Security for Constrained RESTful Environments (OSCORE), to protect DoC later
* **[RFC 8932](https://datatracker.ietf.org/doc/html/rfc8932):** Recommendations for DNS Privacy Service Operators
* **[RFC 9103](https://datatracker.ietf.org/doc/html/rfc9103):** DNS Zone Transfer over TLS (XoT)
* **[RFC 9147](https://datatracker.ietf.org/doc/html/rfc9147):** The Datagram Transport Layer Security (DTLS) Protocol Version 1.3, to protect DoC later
* **[RFC 9156](https://datatracker.ietf.org/doc/html/rfc9156):** DNS Query Name Minimisation to Improve Privacy (Obsoletes RFC 7816)
* **[RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180):** Hybrid Public Key Encryption (HPKE), for ODoH
* **[RFC 9230](https://datatracker.ietf.org/doc/html/rfc9230):** Oblivious DNS over HTTPS (ODoH, Experimental), optional, after DoH
* **[RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250):** DNS over Dedicated QUIC Connections (DoQ)
* **[RFC 9461](https://datatracker.ietf.org/doc/html/rfc9461):** Service Binding Mapping for DNS Servers
* **[RFC 9462](https://datatracker.ietf.org/doc/html/rfc9462):** Discovery of Designated Resolvers (DDR)
* **[RFC 9953](https://datatracker.ietf.org/doc/html/rfc9953):** DNS over the Constrained Application Protocol (DoC), for constrained IoT networks; experimental in dédéns, last of the transports

### Authentication, Linking, and Local Discovery
* **[RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698):** The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
* **[RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762):** Multicast DNS (mDNS)
* **[RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763):** DNS-Based Service Discovery (DNS-SD)
* **[RFC 8659](https://datatracker.ietf.org/doc/html/rfc8659):** DNS Certification Authority Authorization (CAA) Resource Record (Obsoletes RFC 6844)
* **[RFC 8976](https://datatracker.ietf.org/doc/html/rfc8976):** Message Digest for DNS Zones (ZONEMD)

---

## Part 2: Extra, Operational, Niche, and Old/Obsolete RFCs

This section includes older drafts that were superseded, informational RFCs, niche resource records, and operational guidelines that do not define the core modern protocol.

### Obsolete / Historical (The Predecessors)
* **[RFC 882](https://datatracker.ietf.org/doc/html/rfc882) / [RFC 883](https://datatracker.ietf.org/doc/html/rfc883):** The original DNS concepts and specifications (Obsoleted by 1034/1035)
* **[RFC 973](https://datatracker.ietf.org/doc/html/rfc973):** Domain System Changes and Observations (Obsoleted by 1034/1035)
* **[RFC 2065](https://datatracker.ietf.org/doc/html/rfc2065) / [RFC 2535](https://datatracker.ietf.org/doc/html/rfc2535):** Early/Obsolete versions of DNSSEC (Obsoleted by 4033/4034/4035)
* **[RFC 2671](https://datatracker.ietf.org/doc/html/rfc2671):** Original EDNS specification (Obsoleted by 6891)
* **[RFC 2672](https://datatracker.ietf.org/doc/html/rfc2672):** Non-Terminal DNS Name Redirection, original DNAME (Obsoleted by 6672)
* **[RFC 2845](https://datatracker.ietf.org/doc/html/rfc2845):** Original TSIG specification (Obsoleted by 8945)
* **[RFC 2915](https://datatracker.ietf.org/doc/html/rfc2915):** Original NAPTR specification (Obsoleted by 3401-3404)
* **[RFC 4641](https://datatracker.ietf.org/doc/html/rfc4641):** DNSSEC Operational Practices (Obsoleted by 6781)
* **[RFC 6844](https://datatracker.ietf.org/doc/html/rfc6844):** Original CAA specification (Obsoleted by 8659)
* **[RFC 7706](https://datatracker.ietf.org/doc/html/rfc7706):** Decreasing Access Time to Root Servers by Running One on Loopback (Obsoleted by 8806)
* **[RFC 7719](https://datatracker.ietf.org/doc/html/rfc7719):** Old DNS Terminology (Obsoleted by 8499)
* **[RFC 7816](https://datatracker.ietf.org/doc/html/rfc7816):** Experimental QNAME Minimisation (Obsoleted by 9156)
* **[RFC 8499](https://datatracker.ietf.org/doc/html/rfc8499):** DNS Terminology (Obsoleted by 9499)
* **[RFC 8624](https://datatracker.ietf.org/doc/html/rfc8624):** Algorithm Implementation Requirements and Usage Guidance for DNSSEC (Obsoleted by 9904)

### Operational Guidelines & Best Practices
* **[RFC 1591](https://datatracker.ietf.org/doc/html/rfc1591):** Domain Name System Structure and Delegation
* **[RFC 1912](https://datatracker.ietf.org/doc/html/rfc1912):** Common DNS Operational and Configuration Errors
* **[RFC 2182](https://datatracker.ietf.org/doc/html/rfc2182):** Selection and Operation of Secondary DNS Servers (BCP 16)
* **[RFC 3833](https://datatracker.ietf.org/doc/html/rfc3833):** Threat Analysis of the Domain Name System
* **[RFC 4697](https://datatracker.ietf.org/doc/html/rfc4697):** Observed DNS Resolution Misbehavior (BCP 123)
* **[RFC 5358](https://datatracker.ietf.org/doc/html/rfc5358):** Preventing Use of Recursive Nameservers in Reflector Attacks
* **[RFC 5625](https://datatracker.ietf.org/doc/html/rfc5625):** DNS Proxy Implementation Guidelines
* **[RFC 6303](https://datatracker.ietf.org/doc/html/rfc6303):** Locally Served DNS Zones
* **[RFC 6761](https://datatracker.ietf.org/doc/html/rfc6761):** Special-Use Domain Names
* **[RFC 6781](https://datatracker.ietf.org/doc/html/rfc6781):** DNSSEC Operational Practices, Version 2
* **[RFC 6895](https://datatracker.ietf.org/doc/html/rfc6895):** Domain Name System (DNS) IANA Considerations
* **[RFC 8806](https://datatracker.ietf.org/doc/html/rfc8806):** Running a Root Server Local to a Resolver
* **[RFC 8901](https://datatracker.ietf.org/doc/html/rfc8901):** Multi-Signer DNSSEC Models
* **[RFC 8906](https://datatracker.ietf.org/doc/html/rfc8906):** A Common Operational Problem in DNS Servers: Failure to Communicate
* **[RFC 9210](https://datatracker.ietf.org/doc/html/rfc9210):** DNS Transport over TCP - Operational Requirements
* **[RFC 9715](https://datatracker.ietf.org/doc/html/rfc9715):** IP Fragmentation Avoidance in DNS over UDP

### Internationalized Domain Names (IDN)
* **[RFC 3492](https://datatracker.ietf.org/doc/html/rfc3492):** Punycode: A Bootstring encoding of Unicode for IDNA
* **[RFC 5890](https://datatracker.ietf.org/doc/html/rfc5890):** IDNA: Definitions and Document Framework
* **[RFC 5891](https://datatracker.ietf.org/doc/html/rfc5891):** IDNA: Protocol
* **[RFC 5892](https://datatracker.ietf.org/doc/html/rfc5892):** IDNA: The Unicode Code Points
* **[RFC 5893](https://datatracker.ietf.org/doc/html/rfc5893):** IDNA: Right-to-Left Scripts
* **[RFC 5894](https://datatracker.ietf.org/doc/html/rfc5894):** IDNA: Background, Explanation, and Rationale
* **[RFC 5895](https://datatracker.ietf.org/doc/html/rfc5895):** Mapping Characters for IDNA2008

### Data Encodings
* **[RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648):** The Base16, Base32, and Base64 Data Encodings (base64 and hex in presentation format)

### Specialized / Niche Resource Records & Extensions
* **[RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183):** New DNS RR Definitions (AFSDB, RP, X25, ISDN, RT)
* **[RFC 1706](https://datatracker.ietf.org/doc/html/rfc1706):** DNS NSAP Resource Records (Historic)
* **[RFC 1876](https://datatracker.ietf.org/doc/html/rfc1876):** A Means for Expressing Location Information in the Domain Name System (LOC)
* **[RFC 2930](https://datatracker.ietf.org/doc/html/rfc2930):** Secret Key Establishment for DNS (TKEY RR)
* **[RFC 2931](https://datatracker.ietf.org/doc/html/rfc2931):** DNS Request and Transaction Signatures (SIG(0))
* **[RFC 3007](https://datatracker.ietf.org/doc/html/rfc3007):** Secure Domain Name System (DNS) Dynamic Update
* **[RFC 3123](https://datatracker.ietf.org/doc/html/rfc3123):** A DNS RR Type for Lists of Address Prefixes (APL)
* **[RFC 3403](https://datatracker.ietf.org/doc/html/rfc3403):** Dynamic Delegation Discovery System (DDDS) Part Three: The DNS Database (NAPTR)
* **[RFC 3645](https://datatracker.ietf.org/doc/html/rfc3645):** Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG)
* **[RFC 4255](https://datatracker.ietf.org/doc/html/rfc4255):** Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints (SSHFP)
* **[RFC 4398](https://datatracker.ietf.org/doc/html/rfc4398):** Storing Certificates in the Domain Name System (CERT)
* **[RFC 4470](https://datatracker.ietf.org/doc/html/rfc4470):** Minimally Covering NSEC Records and DNSSEC On-line Signing
* **[RFC 5001](https://datatracker.ietf.org/doc/html/rfc5001):** DNS Name Server Identifier (NSID) Option
* **[RFC 6147](https://datatracker.ietf.org/doc/html/rfc6147):** DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers
* **[RFC 7314](https://datatracker.ietf.org/doc/html/rfc7314):** Extension Mechanisms for DNS (EDNS) EXPIRE Option
* **[RFC 7344](https://datatracker.ietf.org/doc/html/rfc7344):** Automating DNSSEC Delegation Trust Maintenance (CDS/CDNSKEY)
* **[RFC 7553](https://datatracker.ietf.org/doc/html/rfc7553):** The Uniform Resource Identifier (URI) DNS Resource Record
* **[RFC 7828](https://datatracker.ietf.org/doc/html/rfc7828):** The edns-tcp-keepalive EDNS0 Option
* **[RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871):** Client Subnet in DNS Queries (EDNS Client Subnet)
* **[RFC 7929](https://datatracker.ietf.org/doc/html/rfc7929):** DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP
* **[RFC 8078](https://datatracker.ietf.org/doc/html/rfc8078):** Managing DS Records from the Parent via CDS/CDNSKEY
* **[RFC 8145](https://datatracker.ietf.org/doc/html/rfc8145):** Signaling Trust Anchor Knowledge in DNSSEC
* **[RFC 8490](https://datatracker.ietf.org/doc/html/rfc8490):** DNS Stateful Operations (DSO)
* **[RFC 8509](https://datatracker.ietf.org/doc/html/rfc8509):** A Root Key Trust Anchor Sentinel for DNSSEC
* **[RFC 9567](https://datatracker.ietf.org/doc/html/rfc9567):** DNS Error Reporting (Report-Channel EDNS option)
* **[RFC 9615](https://datatracker.ietf.org/doc/html/rfc9615):** Automatic DNSSEC Bootstrapping Using Authenticated Signals from the Zone's Operator

### Assorted Informational & Experimental
* **[RFC 1101](https://datatracker.ietf.org/doc/html/rfc1101):** DNS Encoding of Network Names and Other Types
* **[RFC 1480](https://datatracker.ietf.org/doc/html/rfc1480):** The US Domain
* **[RFC 1535](https://datatracker.ietf.org/doc/html/rfc1535):** A Security Problem and Proposed Correction With Widely Deployed DNS Software
* **[RFC 1536](https://datatracker.ietf.org/doc/html/rfc1536):** Common DNS Implementation Errors and Suggested Fixes
* **[RFC 1713](https://datatracker.ietf.org/doc/html/rfc1713):** Tools for DNS debugging
* **[RFC 1794](https://datatracker.ietf.org/doc/html/rfc1794):** DNS Support for Load Balancing
* **[RFC 2317](https://datatracker.ietf.org/doc/html/rfc2317):** Classless IN-ADDR.ARPA delegation
* **[RFC 7129](https://datatracker.ietf.org/doc/html/rfc7129):** Authenticated Denial of Existence in the DNS
* **[RFC 8020](https://datatracker.ietf.org/doc/html/rfc8020):** NXDOMAIN: There Really Is Nothing Underneath
* **[RFC 8767](https://datatracker.ietf.org/doc/html/rfc8767):** Serving Stale Data to Improve DNS Resiliency
