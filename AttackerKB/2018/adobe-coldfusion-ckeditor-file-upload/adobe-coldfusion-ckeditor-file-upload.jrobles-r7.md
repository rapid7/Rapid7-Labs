---
title: Adobe ColdFusion CKEditor file upload
author: jrobles-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 3
topic_disclosure_date: '2018-09-25T13:29:00'
created: '2019-05-09T17:57:27.82511'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 57eb3832-9669-4477-a778-f1c9a3b7bb27
topic_id: 03cf04ce-d3db-4e24-9b1e-9d24864ebb2e
topic_short_id: 0bSiJkpaEG
topic_slug: adobe-coldfusion-ckeditor-file-upload
akb_topic_url: https://attackerkb.com/topics/0bSiJkpaEG/adobe-coldfusion-ckeditor-file-upload
akb_assessment_url: https://attackerkb.com/topics/0bSiJkpaEG/adobe-coldfusion-ckeditor-file-upload#57eb3832-9669-4477-a778-f1c9a3b7bb27
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 3
  exploitability: 3
  offensive-application: not sure
  urgent-to-patch: 4
---

# Adobe ColdFusion CKEditor file upload

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/0bSiJkpaEG/adobe-coldfusion-ckeditor-file-upload#57eb3832-9669-4477-a778-f1c9a3b7bb27).*

---

## Details

Description/Details copy/pasta from Metasploit [module documentation](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/http/coldfusion_ckeditor_file_upload.md).

A file upload vulnerability in the CKEditor of Adobe ColdFusion 11 (Update 14 and earlier), ColdFusion 2016 (Update 6 and earlier), and ColdFusion 2018 (July 12 release) allows unauthenticated remote attackers to upload and execute JSP files through the filemanager plugin.
