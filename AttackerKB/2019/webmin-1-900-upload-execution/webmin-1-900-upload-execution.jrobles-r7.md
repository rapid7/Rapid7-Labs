---
title: Webmin 1.900 Upload Execution
author: jrobles-r7
score: 1
topic_attacker_value: 2
topic_exploitability: 2
topic_disclosure_date: '2019-03-07T05:29:00'
created: '2019-05-09T17:57:20.830454'
revision_date: '2020-02-13T17:12:45.719724'
assessment_id: 5e8acf72-5882-4fd0-8790-764a17f1f905
topic_id: 0fd486b8-c196-4503-bcd9-16c2628dad61
topic_short_id: aPaHTUKr3B
topic_slug: webmin-1-900-upload-execution
akb_topic_url: https://attackerkb.com/topics/aPaHTUKr3B/webmin-1-900-upload-execution
akb_assessment_url: https://attackerkb.com/topics/aPaHTUKr3B/webmin-1-900-upload-execution#5e8acf72-5882-4fd0-8790-764a17f1f905
author_ratings:
  attacker-value: 2
  confidence-in-ratings: 2
  effort-to-develop-exploit: 1
  exploitability: 2
  urgent-to-patch: 3
---

# Webmin 1.900 Upload Execution

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/aPaHTUKr3B/webmin-1-900-upload-execution#5e8acf72-5882-4fd0-8790-764a17f1f905).*

---

## Details

Webmin 1.900 allows authenticated users with "Upload and Download" module access to upload cgi files to a webroot subdirectory and the uploaded files can be executed by sending requests to the web server.
