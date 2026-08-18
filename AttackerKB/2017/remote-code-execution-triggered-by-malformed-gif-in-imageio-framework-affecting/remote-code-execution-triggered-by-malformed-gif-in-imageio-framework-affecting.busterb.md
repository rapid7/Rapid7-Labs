---
title: Remote code execution triggered by malformed GIF in ImageIO framework, affecting most iOS/macOS apps
author: busterb
score: 1
topic_attacker_value: 4
topic_exploitability: 3
topic_disclosure_date: '2017-04-02T01:59:00'
created: '2019-10-09T23:02:01.369679'
revision_date: '2020-02-13T17:12:01.318567'
assessment_id: b2745522-6292-4e87-96b1-df4036cf2317
topic_id: 857fc1a3-ee6c-45de-93a8-a4d31d5ed28f
topic_short_id: NvxYG2X2cL
topic_slug: remote-code-execution-triggered-by-malformed-gif-in-imageio-framework-affecting-most-ios-macos-apps
akb_topic_url: https://attackerkb.com/topics/NvxYG2X2cL/remote-code-execution-triggered-by-malformed-gif-in-imageio-framework-affecting-most-ios-macos-apps
akb_assessment_url: https://attackerkb.com/topics/NvxYG2X2cL/remote-code-execution-triggered-by-malformed-gif-in-imageio-framework-affecting-most-ios-macos-apps#b2745522-6292-4e87-96b1-df4036cf2317
author_ratings:
  attacker-value: 4
  effort-to-develop-exploit: 4
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 1
---

# Remote code execution triggered by malformed GIF in ImageIO framework, affecting most iOS/macOS apps

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/NvxYG2X2cL/remote-code-execution-triggered-by-malformed-gif-in-imageio-framework-affecting-most-ios-macos-apps#b2745522-6292-4e87-96b1-df4036cf2317).*

---

Noticed this while looking into recent iTerm vulnerabilities and thinking about how to exploit iTerm's builtin image rendering and file download capabilities. This seems to have the ability to cause havoc especially on machines that cannot upgrade to newer OSes due to hardware obsoleting by Apple. Curious if there might be other things to look at in NSImage as well.

Marking utility a little lower just because this is a couple-year old vuln.
