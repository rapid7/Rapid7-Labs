---
title: Apache Solr 8.11, 8.20 have unauthenticated JMX server enabled in default config
author: busterb
score: 4
topic_attacker_value: 5
topic_exploitability: 5
topic_disclosure_date: '2019-09-11T22:15:00'
created: '2019-11-20T04:00:24.44119'
revision_date: '2020-02-13T17:11:55.262228'
assessment_id: b2814996-4838-4fbb-9a30-67141090ae0e
topic_id: aa14b243-8e3b-42fa-b2f2-b686b440e2f3
topic_short_id: 108oFmoYe1
topic_slug: apache-solr-8-11-8-20-have-unauthenticated-jmx-server-enabled-in-default-config
akb_topic_url: https://attackerkb.com/topics/108oFmoYe1/apache-solr-8-11-8-20-have-unauthenticated-jmx-server-enabled-in-default-config
akb_assessment_url: https://attackerkb.com/topics/108oFmoYe1/apache-solr-8-11-8-20-have-unauthenticated-jmx-server-enabled-in-default-config#b2814996-4838-4fbb-9a30-67141090ae0e
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 1
  exploitability: 5
  mitigation-strength: 3
  reliability: 5
  stability: 5
  urgent-to-patch: 1
  used-successfully: 5
---

# Apache Solr 8.11, 8.20 have unauthenticated JMX server enabled in default config

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/108oFmoYe1/apache-solr-8-11-8-20-have-unauthenticated-jmx-server-enabled-in-default-config#b2814996-4838-4fbb-9a30-67141090ae0e).*

---

This configuration issue could really affect any version, since it's just someone having left the debug option on in the default config.
Metasploit has had a general scanner for this misconfiguration since 2012 in auxiliary/scanner/misc/java_rmi_server and 2011 in modules/exploits/multi/misc/java_rmi_server. Just noticed https://github.com/rapid7/metasploit-framework/pull/12565 which might be useful as well.

Shodan only shows _maybe_ one host on the internet exposing this port in something that could plausibly look like JMX. The next great internet work this will not be: https://www.shodan.io/search?query=port%3A18983

I'm giving this a high attacker utility but _also_ a low urgency to patch, because the patch is almost irrelevant here. If you're using the default solr config, your solr install probably doesn't work anyway! The patch isn't really required to fix this configuration bug,, and you could be vulnerable with or without updating to a newer version. Even if you patch, if you have the a bad config, it's not necessarily going to auto-update either. Any authenticated vuln scan is probably going to produce misleading results about whether you're actually vulnerable or not, unless it checks your config file. Doing a remote scan is much better.

The mitigation is really just making sure you don't deploy a config that leaves unauth RMI servers on a network, but nothing really stops you from shooting yourself in the foot either. Note that Solr's own docs tell you how to enable this bit, but also it says to not use it in production. https://lucene.apache.org/solr/guide/7_0/using-jmx-with-solr.html
