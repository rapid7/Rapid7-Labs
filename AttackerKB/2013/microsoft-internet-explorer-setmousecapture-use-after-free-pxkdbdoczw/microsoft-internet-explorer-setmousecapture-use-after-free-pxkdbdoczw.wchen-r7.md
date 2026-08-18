---
title: Microsoft Internet Explorer SetMouseCapture Use-After-Free
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-09-18T10:08:00'
created: '2019-09-12T18:07:41.433906'
revision_date: '2020-02-13T17:12:12.369612'
assessment_id: 3fd70e1c-b063-4582-b9ec-ca71b3ee01ce
topic_id: 38b15624-980b-45e2-bde4-ee54bfba9846
topic_short_id: pXKdBDoCZw
topic_slug: microsoft-internet-explorer-setmousecapture-use-after-free
akb_topic_url: https://attackerkb.com/topics/pXKdBDoCZw/microsoft-internet-explorer-setmousecapture-use-after-free
akb_assessment_url: https://attackerkb.com/topics/pXKdBDoCZw/microsoft-internet-explorer-setmousecapture-use-after-free#3fd70e1c-b063-4582-b9ec-ca71b3ee01ce
---

# Microsoft Internet Explorer SetMouseCapture Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/pXKdBDoCZw/microsoft-internet-explorer-setmousecapture-use-after-free#3fd70e1c-b063-4582-b9ec-ca71b3ee01ce).*

---

Exploit Hash: 203aa9b2439cfab4ff1678a227be9a9a

# Information

CVE-2013-3893 is a use-after-free vulnerability that affects Internet Explorer versions 6/7/8/9/10/11.
It was initially found being exploited in Japan. A fix-it workaround is already available at the time
of the writing, no information on when Microsoft will release an official final to address the IE flaw.

A sample of the exploit (in the wild) can be found on VirusTotal, scrumware.org, and jsunpack.

The exploit in the wild is written to target IE8/9, Win XP and Windows 7. Under Win XP, the code is
specifically tweaked to work against languages including English, Chinese, Japanese, Korean, although
its fingerprinting code actually checks these languages: English, Chinese, French, German, Japanese,
Portuguese, Korean, and Russian.  It is safe to say it's designed to work against Windows machines in
Asia, hard to why other languages are fingerprinted but not tweaked.  Either because the author was
lazy to test them, and the fingerprinting code was a lazy copy-and paste.  Or, they can be exploited
successfully without any tweaks. Under Windows 7, Office 2007 is also required to engauge the target,
however the fingerprinting code also checks Office 2010, which seems rather unnecessary.  The exploit
will attempt again and again until either the browser crashes, or indefinitely. After exploitation,
the exploit will set a cookie on the victim machine as a way to avoid hitting the same target again.

The vulnerability is due to how the mshtml!CDoc::SetMouseCapture function handles a reference during
an event. An attacker first can setup two elements, where the second is the child of the first, and
then setup a onlosecapture event handler for the parent element. The onlosecapture event seems to
require two setCapture() calls to trigger, one for the parent element, one for the child. When the
setCapture() call for the child element is called, it finally triggers the event, which allows the
attacker to cause an arbitrary memory release using document.write(), which in particular frees up
a 0x54-byte memory.  The exact size of this memory may differ based on the version of IE. After the
free, an invalid reference will still be kept and pass on to more functions, eventuall this arrives
in function MSHTML!CTreeNode::GetInterface, and causes a crash (or arbitrary code execution) when
this function attempts to use this reference to call what appears to be a PrivateQueryInterface due
to the offset (0x00).
