---
title: Internet Explorer RCE through scripting engine memory corruption (IE 9, 10, 11)
author: busterb
score: 1
topic_attacker_value: 4
topic_exploitability: 0
topic_disclosure_date: '2019-11-12T19:15:00'
created: '2019-11-19T23:25:29.3873'
revision_date: '2020-02-13T17:11:55.474912'
assessment_id: f5ff9db8-2e46-4529-8fce-76fca251aeab
topic_id: 0d37ca24-1a96-4579-9fde-acadb531aefe
topic_short_id: ZdofRS9HCI
topic_slug: internet-explorer-rce-through-scripting-engine-memory-corruption-ie-9-10-11
akb_topic_url: https://attackerkb.com/topics/ZdofRS9HCI/internet-explorer-rce-through-scripting-engine-memory-corruption-ie-9-10-11
akb_assessment_url: https://attackerkb.com/topics/ZdofRS9HCI/internet-explorer-rce-through-scripting-engine-memory-corruption-ie-9-10-11#f5ff9db8-2e46-4529-8fce-76fca251aeab
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 4
  urgent-to-patch: 4
---

# Internet Explorer RCE through scripting engine memory corruption (IE 9, 10, 11)

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/ZdofRS9HCI/internet-explorer-rce-through-scripting-engine-memory-corruption-ie-9-10-11#f5ff9db8-2e46-4529-8fce-76fca251aeab).*

---

Since this is being exploited in the wild, and affects a wide range of Internet Explorer versions, it looks like it will have some longterm success in targeted phishing and malvertizing campaigns. IE might be down to just 2% of usage, but it's the only option out of the box on most WIndows Server versions, so it's at least easy-ish to be running a vulnerable version until you can get patches applied or download a different browser first.

Probably only urgent to patch if you actually use it.
