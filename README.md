# wasure
finding the things you've forgetten about

A tool which makes use of Open Source and Public datasets to identify third and fourth party dependencies
specifically to identify ones which could be abused.

## Scanners

**DNS Scanner**
Resolve DNS A, AAAA, CNAME and NS to identify IP and Name Servers.

**Certificate Transparency Scanner**
Identify assets through certificate issuance logs.

## Not Implmented

**HTTP Scanner** (partially implemented)  
Downloads webpages to identify links, included assets such as JavaScript, Style Sheets and TLS Certificates.

**IP Scanner** (partially implmented)   
(implemented)  Owner, geolocation

**Port Scanner** (not implemented)   
(not implemented) Open/Closed status and banners from small subset of ports (22,80,443)

**Version Scanner** (not implemented)   
(not implemented) Identify versions of JavaScript includes

**Reputation Scanner** (not implemented)   
(not implemented) Lookup domain and IP on abuse lists
