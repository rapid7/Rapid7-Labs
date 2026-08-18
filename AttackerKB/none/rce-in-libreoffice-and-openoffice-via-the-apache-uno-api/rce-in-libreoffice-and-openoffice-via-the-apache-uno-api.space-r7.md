---
title: RCE in LibreOffice and OpenOffice via the Apache UNO API
author: space-r7
score: 1
topic_attacker_value: 5
topic_exploitability: 2
created: '2019-09-12T18:07:10.676236'
revision_date: '2020-02-13T17:12:19.760769'
assessment_id: 490d7f09-7b32-4d65-9cbc-cb784362cb70
topic_id: c7f37784-ea9e-49f2-a41c-1401def6f87a
topic_short_id: jYdkeAl1E1
topic_slug: rce-in-libreoffice-and-openoffice-via-the-apache-uno-api
akb_topic_url: https://attackerkb.com/topics/jYdkeAl1E1/rce-in-libreoffice-and-openoffice-via-the-apache-uno-api
akb_assessment_url: https://attackerkb.com/topics/jYdkeAl1E1/rce-in-libreoffice-and-openoffice-via-the-apache-uno-api#490d7f09-7b32-4d65-9cbc-cb784362cb70
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 3
  effort-to-develop-exploit: 2
  exploitability: 2
  urgent-to-patch: 1
  used-successfully: 5
---

# RCE in LibreOffice and OpenOffice via the Apache UNO API

*Assessment by space-r7, archived from [AttackerKB](https://attackerkb.com/topics/jYdkeAl1E1/rce-in-libreoffice-and-openoffice-via-the-apache-uno-api#490d7f09-7b32-4d65-9cbc-cb784362cb70).*

---

## Details

The `soffice` binary allows passing arguments in order to listen on a host ip and port. Axel Boesenach found that the Apache UNO API that acts as a communication bridge to the `soffice` process
can execute shell commands through the `XSystemShellExecute` execute module. This exploit is useful in that exploitation comes easy through the usage of a Python library. Discovering targets running
this process are likely rare, given that the functionality exploited here is rarely used, and there is no default port that this service listens on. The effort to exploit this vulnerability was
given a higher rating due to these caveats.
