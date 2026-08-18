---
title: Wordpress Post Meta Entry RCE
author: space-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 2
topic_disclosure_date: '2019-02-20T03:29:00'
created: '2019-05-09T17:57:28.27953'
revision_date: '2020-02-13T17:12:43.852805'
assessment_id: 8005e4d3-49f5-4f05-8a2a-1bca7d611405
topic_id: 789cfcc3-5972-48e6-a3ee-521d7c07797a
topic_short_id: RtAdbzXGk1
topic_slug: wordpress-post-meta-entry-rce
akb_topic_url: https://attackerkb.com/topics/RtAdbzXGk1/wordpress-post-meta-entry-rce
akb_assessment_url: https://attackerkb.com/topics/RtAdbzXGk1/wordpress-post-meta-entry-rce#8005e4d3-49f5-4f05-8a2a-1bca7d611405
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 4
  exploitability: 2
  urgent-to-patch: 5
---

# Wordpress Post Meta Entry RCE

*Assessment by space-r7, archived from [AttackerKB](https://attackerkb.com/topics/RtAdbzXGk1/wordpress-post-meta-entry-rce#8005e4d3-49f5-4f05-8a2a-1bca7d611405).*

---

## Details

This exploit requires authentication and either the `php-imagick` or `php-gd` extension to be installed. Exploiting this vulnerability with only
the `php-gd` extension installed will require more work when crafting the JPEG because the `php-gd` extension compresses the image and strips it of
its exif metadata. This is still a valuable exploit due to the large user base of the application.
