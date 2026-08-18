---
title: Insecure RDP
author: zeroSteiner
score: 8
topic_attacker_value: 5
topic_exploitability: 5
created: '2020-10-09T18:36:46.905083'
revision_date: '2021-06-07T17:56:31.244358'
assessment_id: 490fe3fa-01b7-4972-a08c-a1bccb7b3d3d
topic_id: 86f390bb-7946-4223-970a-d493d6dd1e0a
topic_short_id: SjeQNRWoQU
topic_slug: insecure-rdp
akb_topic_url: https://attackerkb.com/topics/SjeQNRWoQU/insecure-rdp
akb_assessment_url: https://attackerkb.com/topics/SjeQNRWoQU/insecure-rdp#490fe3fa-01b7-4972-a08c-a1bccb7b3d3d
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Initial Access
---

# Insecure RDP

*Assessment by zeroSteiner, archived from [AttackerKB](https://attackerkb.com/topics/SjeQNRWoQU/insecure-rdp#490fe3fa-01b7-4972-a08c-a1bccb7b3d3d).*

---

Over the past couple of years (2018-2020) attacks against RDP have become more and more common. Recent improvements in attacker-related tooling can be contributed to generally available and mature projects targeting RDP and a number of remotely exploitable vulnerabilities being disclosed.

# Memory Corruption Flaws
One of the best examples of this is [CVE-2019-0708](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep) [archive](https://github.com/rapid7/Rapid7-Labs/blob/main/AttackerKB/2019/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep/README.md) (AKA BlueKeep) which was an unauthenticated, remotely exploitable use-after-free in RDP. This particular vulnerability was able to be developed to yield semi-reliable code execution and is widely utilized by attackers. Following this, [CVE-2019-1182](https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow) [archive](https://github.com/rapid7/Rapid7-Labs/blob/main/AttackerKB/2019/dejablue-rdp-heap-overflow/README.md) (AKA DejaBlue) was discovered as well. This particular bug was a heap corruption within the server's dynamic channel handling. While this vulnerability has not to this date had exploitat code released, it also contributed to the popularity of RDP vulnerability research in 2019. 

# Why RDP As An Attack Surface?
Regardless of code execution-type vulnerabilities, RDP is an attractive attack surface for the following reasons:
* It's commonly accessible internally and relatively accessible externally
* It's common that non-administrative users can authenticate to it, offering an initial foothold to attackers
* The service can yield version information about the host operating system
* Established sessions can be hijacked using publicly documented tools techniques and procedure (TTPs)
* In addition to offering a graphical interface to the desktop session, it can also be used to mount drives and transfer files

When compared to an interface such as SMB for the purpose of lateral movement, RDP offers a much larger degree of freedom for the attacker. Using SMB, attackers are able to use a small number of techniques to achieve code execution such as PSexec. Alternatively, RDP through it's graphical interface and file transfer capabilities offers attackers near limitless possibilities. This number of possibilities directly improves the attackers evasion capabilities as they can easily adapt and shift techniques that are blocked through whatever sort of endpoint protection maybe present. Furthermore, SMB as an attack surface is very well know and widely documented. For those reasons, and the fact that there are choke points from an attacker workflow perspective, there are mature defenses and controls in place (such as event monitoring) that are either not applicable to or are less effective when compared to RDP.
