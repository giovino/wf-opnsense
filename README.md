# wf-opnsense

## Introduction

This is some sample code of how you could submit firewall log data from OPNsense to Whiteface.

## Requirements

1. A [Whiteface](https://whiteface.csirtgadgets.com) account
1. A Whiteface account token; within Whiteface:
  1. Select your username
  1. Select "tokens"
  1. Select "Generate Token
1. A Whiteface feed; within Whiteface
  1. Select (the plus sign)
  1. Select Feed
  1. Choose a feed name (e.g. port scanners)
  1. Choose a feed description (hosts blocked in firewall logs)
1. A router/firewall with OPNsense installed
 * Pfsense would likely work but it is untested
 * You must have root + shell access

## Install
1. SSH into the OPNsense router (become root)
1. change to root directory

 ```bash
$ cd /root
 ```
1. Download the wf-opnsense.py script using curl

 ```bash 
$ curl -O curl -O https://raw.githubusercontent.com/giovino/wf-opnsense/master/wf-opnsense.py
 ```
1. edit wf-opnsense.py to add (WHITEFACE_USER, WHITEFACE_FEED, WHITEFACE_TOKEN)

 ```bash
vi wf-opnsense.py
 ```
1. Edit the root crontab

 ```bash
$ crontab -e
 ```
Add the following

 ```bash
*/5 * * * * /usr/local/bin/python2.7 /root/wf-opnsense.py 2>&1 | /usr/bin/logger -t whiteface
  ```
