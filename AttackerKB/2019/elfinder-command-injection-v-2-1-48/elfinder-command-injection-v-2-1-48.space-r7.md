---
title: elFinder Command Injection v<2.1.48
author: space-r7
score: 2
topic_attacker_value: 3
topic_exploitability: 4
topic_disclosure_date: '2019-02-26T19:29:00'
created: '2019-05-09T17:57:31.410878'
revision_date: '2020-03-20T00:25:04.308697'
assessment_id: 4deb3af5-cc38-421d-84b2-f17c24456939
topic_id: ca9335f6-b89e-4233-b4e4-8e3099aaee8f
topic_short_id: RHDTS1mo2x
topic_slug: elfinder-command-injection-v-2-1-48
akb_topic_url: https://attackerkb.com/topics/RHDTS1mo2x/elfinder-command-injection-v-2-1-48
akb_assessment_url: https://attackerkb.com/topics/RHDTS1mo2x/elfinder-command-injection-v-2-1-48#4deb3af5-cc38-421d-84b2-f17c24456939
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 4
  exploitability: 4
  urgent-to-patch: 5
---

# elFinder Command Injection v<2.1.48

*Assessment by space-r7, archived from [AttackerKB](https://attackerkb.com/topics/RHDTS1mo2x/elfinder-command-injection-v-2-1-48#4deb3af5-cc38-421d-84b2-f17c24456939).*

---

## Details

The PHP component in the elFinder software allows unauthenticated users to upload and manipulate images.
While performing image manipulation on a JPEG, elFinder passes the file's name unsanitized to a command line utility called `exiftran`.
By inserting arbitrary code into the JPEG's file name, the code will get passed to the exiftran utility and be executed.

This exploit requires that `exiftran` be installed to work. If `exiftran` is not installed, then the software opts to use `jpegtran`,
which removes exploitability. Despite the caveat listed previously, this is still a valuable exploit.
