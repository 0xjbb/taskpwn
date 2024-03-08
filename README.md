# Taskpwn

## Description

Taskpwn remotely enumerates the task scheduler and dumps any tasks that are ran by a domain user, it also pulls the users username and groups.


This was created because sometimes you might find a bat script or exe running as a DA or high priv and I wanted a faster way to check that rather than logging in via RDP.

## Requirements

- impacket
## Features 

- Enumerate Single or Multiple hosts for Scheduled tasks remotely
- Dump credentials for scheduled tasks
- Remotely update task for exploitation (WIP)

## Usage

### Enum with Domain User on a Single Target

`python3 taskpwn.py example.local/Administrator:Passw0rd 10.10.10.10`


### Enum with Domain User on a Multiple Targets

`python3 taskpwn.py example.local/Administrator:Passw0rd 10.10.10.0/24`


### Enum with Local Admin on a Single Target

`python3 taskpwn.py example.local/Administrator:Passw0rd 10.10.10.10`


### Enum with Local Admin on a Multiple Targets

`python3 taskpwn.py example.local/Administrator:Passw0rd 10.10.10.0/24`

## Bug?

If you find one either create an issue or ideally fix it and PR.
