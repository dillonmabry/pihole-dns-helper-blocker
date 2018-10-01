## PiHole/ThreatCrowd Project
Project to integrate DNS domains from PiHole into ThreatCrowd by performing relationship checks between domains
Utilize ThreatCrowd API by running near-real time communication between PiHole and a temporary staging database in order to update Regex rules, save known IPs of listed threats, as well as analysis for known malware/threats

## Quick Aggregates (Top malicious IPs by country, top malicious files by domain)
sqlite3 pihole-metadata.db "select country_code, count(distinct ip_address) as ips from ipgeos group by country_code order by ips desc limit 10" 
sqlite3 pihole-metadata.db "select parent_domain, count(distinct hash) as dfile from files group by parent_domain order by dfile desc limit 20"

### TODO:
- [X]  Integrate file hashes from known threats to be saved as staging data
- [X]  Integrate geolocation for origin lookup
- [ ]  Create view to perform malware analysis of known threats
- [ ]  Expand capabilities of PiHole by using a FaaS type infrastructure to asynchronously process DNS hits and check whether it is a known threat
- [ ]  Continue metadata analysis of malware and statistics, possibly in future develop algorithms to detect DNS lookups and process on the fly
