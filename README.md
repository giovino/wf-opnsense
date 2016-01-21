# wf-opnsense

## Introduction

This is a sample script demonstrating how you could submit firewall log data from OPNsense to csirtg.io.

## Requirements

1. A [csirtg.io](https://csirtg.io/) account
1. An account token; within csirtg.io:
  1. Select your username
  1. Select "tokens"
  1. Select "Generate Token
1. A csirtg.io feed
  1. Select (the plus sign)
  1. Select Feed
  1. Choose a feed name (e.g. port scanners)
  1. Choose a feed description (hosts blocked in firewall logs)
1. A router/firewall with OPNsense installed
 * Pfsense would likely work but it is untested
 * You must have root + shell access

## Goals

1. To demonstrate how you interact with csirtg.io without using the SDK
1. To not use any python libraries that were not already installed with OPNsense

## Install
1. SSH into the OPNsense router (become root)
1. change to root directory

 ```bash
$ cd /root
 ```
1. Download the wf-opnsense.py script using curl

 ```bash 
$ curl -O https://raw.githubusercontent.com/giovino/wf-opnsense/master/wf-opnsense.py
 ```
1. edit wf-opnsense.py to fill in (CSIRTG_USER, CSIRTG_FEED, CSIRTG_TOKEN)

 ```bash
vi wf-opnsense.py
 ```
1. Edit the root crontab

 ```bash
$ crontab -e
 ```
Add the following

 ```bash
*/5 * * * * /usr/local/bin/python2.7 /root/wf-opnsense.py 2>&1 | /usr/bin/logger -t csirtg.io
  ```
