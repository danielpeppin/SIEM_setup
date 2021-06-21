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

To detect and alert for brute force attacks to the webserver a simple rule to count all packetbeat transactions. Since our targeted server has very low traffic (it is not a real, production server), there will be a very low threshold for anomolous traffic quantity. A threshold of 3000 packetbeat transactions sits comfortably above the baseline traffic, but is also easily exceeded by a dirb scan and also potentially a nmap port scan. When the number of packetbeat transactions exceeds 3000 for 1s, an alert is triggered.

![baseline: excess traffic](https://github.com/danielpeppin/SIEM_setup/blob/main/baseline_network_traffic.PNG)

An alert is set up to trigger counting all packetbeat documents, exceeding 3000 for last 1 minute:

![alert: excess traffic](https://github.com/danielpeppin/SIEM_setup/blob/main/trigger_network_traffic.PNG)

A dashboard is setup to monitor the number of packetbeat transactions over time:

![dashboard: excess_traffic](https://github.com/danielpeppin/SIEM_setup/blob/main/dashboard_network_traffic.PNG)

2) wpscan

To detect and alert for a wpscan, the user_agent field is checked for the user_agent "WPScan v3.7.8 (https://wpscan.org/)". The presence of packetbeat transactions containing user_agent.original "WPScan v3.7.8 (https://wpscan.org/)" will trigger an alert. Ideally, a wildcard can be used to keep the alert functioning for any and all versions of wpscan.

An alert is set up, using JSON code, to check user_agent.original for "WPScan v3.7.8 (https://wpscan.org/)" and create an alert:

![alert: wpscan_JSON](https://github.com/danielpeppin/SIEM_setup/blob/main/trigger_wpscan.PNG)

A dashboard is setup to monitor the useragents being used on the webserver:

![dashboard: wpscan](https://github.com/danielpeppin/SIEM_setup/blob/main/dashboard_wpscan.PNG)

3) Root Escalation

To detect and alert for all sudo authentications, the filebeat field "system.auth.sudo.user" containing "root" will be checked for. Any and all instances of these events in filebeat will be alerted for (threshold for alert is equal to or larger than 1 instance for 1s). The dashboard is configured to show the time of the event and the user account that commited the sudo escalation.

An alert is set up to look for all instances of ystemauth.sudo.user, exceeding 0 for last minute:

![sudo_root_escalation](https://github.com/danielpeppin/SIEM_setup/blob/main/trigger_root_escalation.PNG)

A dashboard is set up to monitor for and show time of all sudo escelations

![sudo_root_escalation](https://github.com/danielpeppin/SIEM_setup/blob/main/dashboard_sudo_escalation.PNG)

4) SSH Session Initiation

To detect and alert for all ssh session initiations, the filebeat field "system.auth.ssh.event" containing "accepted" will be checked for. Again, any and all instances of these events in filebeat will be alerted for (threshold for alerting is set to equal to or greater than 1 instances for 1s). The dashboard is configured to show the time of the event and the user account that was authenticated for ssh.

An alert is set up to look for all instances of system.auth.ssh.event, triggerin an all events:

![alert: ssh_authentication](https://github.com/danielpeppin/SIEM_setup/blob/main/trigger_ssh_authentication.PNG)

A dashboard to list all ssh authentications

![daskhboard: ssh_authentication](https://github.com/danielpeppin/SIEM_setup/blob/main/dashboard_ssh_session.PNG)

## Validation

With the alerts set and the dashboard created, an attack is performed to validate that the alerts are functioning. As a bonus we will see observe the attack visually on our dashboard.

The attack sequence is as follows:

1) nmap scan
2) dirb scan
3) wpscan
4) ssh with user stephen
5) find password hash for user michael
6) ssh with user michael
7) sudo command as user michael


We can see alerts being triggered from each stage of the attack

![list of alerts](https://github.com/danielpeppin/SIEM_setup/blob/main/alerts_triggered.PNG)

THe nmap scan and/or dirb scan triggered the "HTTP Network Traffic" rule several times. Two successfull SSH authentications triggered the "SSH Session Initiated" both times. The root escalation alert was triggered 1 time, and the wpscan alert was triggered 1 time. We will have realtime indication of these events as they occur. 

We can see visually the traffic spike, and the logging of key occurances like ssh authentication and sudo escalation

![dashboard during attack](https://github.com/danielpeppin/SIEM_setup/blob/main/attack_dashboard.PNG)

There is a large traffic spike, seemingly from the nmap and/or dirb scan. There is a log of multiple ssh login attempts including 2 successful ones. There is a log of a sudo escalted command being run, by steven. THere is also evidence of a wpscan as per the WPScan user agent being used. 

We have
