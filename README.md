## PiHole/ThreatCrowd Project
Project to integrate DNS domains from PiHole into ThreatCrowd by performing relationship checks between domains
Utilize ThreatCrowd API by running near-real time communication between PiHole and a temporary staging database in order to update Regex rules, save known IPs of listed threats, as well as analysis for known malware/threats

### TODO:
- [] Create view to perform malware analysis of known threats
- [] Expand capabilities of PiHole by using a FaaS type infrastructure to asynchronously process DNS hits and check whether it is a known threat
- [] Continue metadata analysis of malware and statistics, possibly in future develop algorithms to detect DNS lookups and process on the fly
