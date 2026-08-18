---
title: Sharetronix <= 3.1.1 Two PHP Code Injection Vulnerabilities
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2014-06-13T14:55:00'
created: '2019-09-12T18:07:18.876497'
revision_date: '2020-02-13T17:12:17.770992'
assessment_id: f776a930-6ce7-4ac4-8184-25fa4a877415
topic_id: 8f822f76-2881-49da-a6ad-12cfd9da2407
topic_short_id: qVTbaFNMju
topic_slug: sharetronix-3-1-1-two-php-code-injection-vulnerabilities
akb_topic_url: https://attackerkb.com/topics/qVTbaFNMju/sharetronix-3-1-1-two-php-code-injection-vulnerabilities
akb_assessment_url: https://attackerkb.com/topics/qVTbaFNMju/sharetronix-3-1-1-two-php-code-injection-vulnerabilities#f776a930-6ce7-4ac4-8184-25fa4a877415
---

# Sharetronix <= 3.1.1 Two PHP Code Injection Vulnerabilities

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/qVTbaFNMju/sharetronix-3-1-1-two-php-code-injection-vulnerabilities#f776a930-6ce7-4ac4-8184-25fa4a877415).*

---

According to the advisory: http://karmainsecurity.com/KIS-2013-11

1) Input passed via the “activities_text” POST parameter to /services/activities/set is not properly sanitised before being used in a call to the “preg_replace()” function with the “e” modifier in the /system/classes/class_post.php script. This can be exploited to inject and execute arbitrary PHP code.

2) Input passed via the “comments_text” POST parameter to /services/comments/set is not properly sanitised before being used in a call to the “preg_replace()” function with the “e” modifier in the /system/classes/class_postcomment.php script. This can be exploited to inject and execute arbitrary PHP code.


And: No official solution is currently available (at the time of advisory publication).

Downloaded Sharetronix 3.1.1 from the official website and found it:

* class_postcomment.php

```
$message	= htmlspecialchars($this->comment_message);

if( FALSE!==strpos($message,'http://') || FALSE!==strpos($message,'http://') || FALSE!==strpos($message,'ftp://') ) {
	$message	= preg_replace('#(^|\s)((http|https|ftp)://\w+[^\s\[\]]+)#ie', 'post::_postparse_build_link("\\2", "\\1")', $message);
}
```


* class_post.php

```
$message	= htmlspecialchars($this->post_message);
if( FALSE!==strpos($message,'http://') || FALSE!==strpos($message,'http://') || FALSE!==strpos($message,'ftp://') ) {
	$message	= preg_replace('#(^|\s)((http|https|ftp)://\w+[^\s\[\]]+)#ie', 'post::_postparse_build_link("\\2", "\\1")', $message);
}
```

Unfortunately, in both cases, htmlspecialchars is called over $this->comment_message or $this->post_message, so, evenwhen the preg_replace with /e flag is there, you need " to scape, unfortunately htmlspecialchars is htmlencoding " (double quotes).

I guess it was silently patched or something like that, unfortunately, I haven't access to older versions, I can't find nothing in the vendor homepage :(
