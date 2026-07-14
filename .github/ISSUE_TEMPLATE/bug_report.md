---
name: Bug report
about: Something doesn't work as expected
title: ''
labels: bug
assignees: ''
---

**What happened**
A clear description of the bug.

**Steps to reproduce**
1. `./telegloomy create` / `join <code>` ...
2. ...

**Expected behavior**
What you expected to happen instead.

**Full log output**
Paste the full stderr output from both peers if relevant (redact the pairing
code if you're worried about it, though it's single-use and useless without
the live session anyway).

```
paste here
```

**Environment**
- OS / distro:
- Build: `make` / `make telegloomy-voice`
- Same LAN or over the internet?
- Firewall in use (ufw / firewalld / Windows Defender / none)?

**Did this involve a firewall or NAT issue?**
If hole punching failed or was asymmetric, please also check
`sudo journalctl -k | grep -i UFW` (or your firewall's log) around the time of
the failure and paste relevant lines — see NAT-TRAVERSAL.md for context.
