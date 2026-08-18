---
title: Microsoft Internet Explorer SetMouseCapture Use-After-Free
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-10-09T14:44:00'
created: '2019-09-12T18:07:46.023783'
revision_date: '2020-02-13T17:12:10.765401'
assessment_id: 68bd45ac-ddcc-48af-a282-99745f7f45bd
topic_id: 3c7b4cf8-80c4-45a5-9363-afaa8c364d11
topic_short_id: KfWrR0dJNU
topic_slug: microsoft-internet-explorer-setmousecapture-use-after-free
akb_topic_url: https://attackerkb.com/topics/KfWrR0dJNU/microsoft-internet-explorer-setmousecapture-use-after-free
akb_assessment_url: https://attackerkb.com/topics/KfWrR0dJNU/microsoft-internet-explorer-setmousecapture-use-after-free#68bd45ac-ddcc-48af-a282-99745f7f45bd
---

# Microsoft Internet Explorer SetMouseCapture Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/KfWrR0dJNU/microsoft-internet-explorer-setmousecapture-use-after-free#68bd45ac-ddcc-48af-a282-99745f7f45bd).*

---

# Information

"MS13-080 also fixes a second CVE vulnerability that has been exploited in limited attacks over the
web. This issue is a user-after-free vulnerability in CDisplayPointer triggered with
“onpropertychange” event handler. This exploit was found cached on a popular Javascript analysis
website and reported to us. The exploit code for this issue, released probably around mid-September
, uses heap-spray to allocate a small ROP chain around address 0x14141414 and is designed to target
only IE8 running on Windows XP for Korean and Japanese language-based users" - Microsoft

This issue is a use-after-free vulnerability in CDisplayPointer via the use of a "onpropertychange"
event handler. To setup the appropriate buggy conditions, we first craft the DOM tree in a specific
order, where a CBlockElement comes after the CTextArea element. There are also other ways to acheive
the same results, for example: Replace CBlockElement with another CTextArea. One possible explanation
for that is perhaps the second element needs to hold a reference of the parent.

If we use a select() function for the CTextArea element, two important things will happen: a
CDisplayPointer object will be created for CTextArea, and it will also trigger another event called
"onselect". The "onselect" event will allow us to setup for the actual event handler we want to abuse
- the "onpropertychange" event. Since the CBlockElement is a child of CTextArea, if we do a node swap
of CBlockElement in "onselect", this will trigger "onpropertychange".  During "onpropertychange" event
handling, a free of the CDisplayPointer object can be forced by using an "Unslect" (other approaches
also apply), but a reference of this freed memory will still be kept by CDoc::ScrollPointerIntoView,
specifically after the CDoc::GetLineInfo call, because it is still trying to use that to update
CDisplayPointer's position. When this invalid reference arrives in QIClassID, a crash finally occurs
due to accessing the freed memory. By controlling this freed memory, it is possible to achieve arbitrary
code execution under the context of the user.

The trigger of the vulnerability seems to be based on previously discovered bugs, specifically
CVE-2012-4969 (ie_execcommand_uaf) and CVE-2013-1347 (ie_cgenericelement_uaf). This just means
that the browser fuzzing tool was tweaked based on these references. There is some junk code in
the trigger. For example, contentEditable does not have to be enabled, but this attribute this
commonly enabled by fuzzers because of document selection. There is also multiple junk CollectGarbage
calls, with Math.atan2() debugging messages around them - which is also an indicator that the exploit
author was still in the process of understanding what they're for. The vulnerability seems to only
work on Internet Explorer 8 (tested on Win 7 and Win XP), older versions might be affected, did not
check. It does not work against IE9 (tested).

The exploit actually looks more like a proof-of-concept rather than weaponized. The Math.atan2()
functions are used as a way to print debugging messages in WinDBG is a strong indicator that this poc
was possibly incomplete. It's possible that the experimental version was leaked on the web, so
it was rushed into deployment.

The heap grooming technique is exactly the same as the CVE-2013-3893 - it'd use the
setAttribute() function trigger heap allocations, creates 2000 of them, and the frees half of them.
This also indicates it's probably done by the same author.
