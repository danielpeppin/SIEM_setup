# SIEM Setup

## Goal

Using Beats packages, Kibana, and Elasticsearch, generate a dashboard and watcher alert rules that will detect a predefined attach in progress. 

- nmap scan
- dirb scan
- wpscan username enumeration
- ssh session initation
- sudo escalation

## Network Topology

Host: ELK Stack (monitoring)
- 192.168.1.100

Host: Target Server
- 192.168.1.110
- SSH
- HTTP

Host: Attack Machine (Kali Linux)
- 192.168.1.90

## Setting Alerts

1) Excess Traffic

To detect and alert for brute force attacks to the webserver a simple rule to count all packetbeat transactions. Since our targeted server has very low traffic (it is not a real, production server), there will be a very low threshold for anomolous traffic quantity. A threshold of 500 packetbeat transactions sits comfortably above the baseline traffic, but is also easily exceeded by a dirb scan and also potentially a nmap port scan. When the number of packetbeat transactions exceeds 500 for 1s, an alert is triggered.

![excess_traffic](https://github.com/danielpeppin/SIEM_setup/blob/main/excess_traffic_threshold.PNG)

Packetbeat transaction counts during baseline operation up to 11:17:00, followed by an nmap scan and a subsequent dirb scan. Dotted line represents the threshold for alert triggering.

2) wpscan

To detect and alert for a wpscan, the user_agent field is checked for the user_agent "WPScan v3.7.8 (https://wpscan.org/)". The presence of packetbeat transactions containing user_agent.original "WPScan v3.7.8 (https://wpscan.org/)" will trigger an alert. Ideally, a wildcard can be used to keep the alert functioning for any and all versions of wpscan.

![excess_traffic](https://github.com/danielpeppin/SIEM_setup/blob/main/wpscan_watcher.PNG)

JSON code used to check user_agent.original for "WPScan v3.7.8 (https://wpscan.org/)"

![wpscan_JSON](https://github.com/danielpeppin/SIEM_setup/blob/main/wpscan_watcher2.PNG)

wpscan triggering several instances of user_agent.original equal to "WPScan v3.7.8 (https://wpscan.org/)"

3) Root Escalation

To detect and alert for all sudo authentications, the filebeat field "system.auth.sudo.user" containing "root" will be checked for. Any and all instances of these events in filebeat will be alerted for (threshold for alert is equal to or larger than 1 instance for 1s). The dashboard is configured to show the time of the event and the user account that commited the sudo escalation.

![sudo_root_escalation](https://github.com/danielpeppin/SIEM_setup/blob/main/root_escalation_dashboard.PNG)

4) SSH Session Initiation

To detect and alert for all ssh session initiations, the filebeat field "system.auth.ssh.event" containing "accepted" will be checked for. Again, any and all instances of these events in filebeat will be alerted for (threshold for alerting is set to equal to or greater than 1 instances for 1s). The dashboard is configured to show the time of the event and the user account that was authenticated for ssh.

![ssh_authentication](https://github.com/danielpeppin/SIEM_setup/blob/main/ssh_authentication_dashboard.PNG)

