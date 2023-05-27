# Taskpwn

## Description

Taskpwn remotely enumerates the task scheduler and dumps any tasks that are ran by a domain user, it also pulls the users username and groups.

This was created because sometimes you might find a bat script or exe running as a DA or high priv and I wanted a faster way to check that rather than logging in via RDP.

## Requirements

- impacket

## Usage

`python3 taskpwn example.local/Administrator:Passw0rd@10.10.10.5`


## Bug?

It will definitely have bugs because I'm not a great programmer, if you find one either create an issue or ideally fix it and PR.