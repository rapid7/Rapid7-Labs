---
title: Liferay CE 6.0.2 Java Deserialization
author: theguly
score: 2
topic_attacker_value: 4
topic_exploitability: 3
created: '2020-03-02T17:11:18.890438'
revision_date: '2020-03-29T13:27:35.813552'
assessment_id: 300d9449-2a79-41f5-9c02-c888b6bd8012
topic_id: 8bd2e977-683c-4857-92db-97750f4d6add
topic_short_id: Gc4Zjo1YmW
topic_slug: liferay-ce-6-0-2-java-deserialization
akb_topic_url: https://attackerkb.com/topics/Gc4Zjo1YmW/liferay-ce-6-0-2-java-deserialization
akb_assessment_url: https://attackerkb.com/topics/Gc4Zjo1YmW/liferay-ce-6-0-2-java-deserialization#300d9449-2a79-41f5-9c02-c888b6bd8012
author_ratings:
  attacker-value: 4
  exploitability: 3
  tags:
  - common_enterprise
  - easy_to_develop
  - obscure_configuration
  - post_auth
---

# Liferay CE 6.0.2 Java Deserialization

*Assessment by theguly, archived from [AttackerKB](https://attackerkb.com/topics/Gc4Zjo1YmW/liferay-ce-6-0-2-java-deserialization#300d9449-2a79-41f5-9c02-c888b6bd8012).*

---

on 29th of january 2020 this github[1] repo came up, with some newsfeed, speakin about a RCE via deserialization on Liferay 6.0.2

i'm aware that liferay is widely used to build both internal and internet-facing webapp, and a possible preauth RCE would be awesome.

actually i don't remember which post i read first, because github repo doesn't speak about any version, but i'm sure i've read somewhere 6.0.2: also exploit-db speaks about 6.0.2, if my memory plays tricks on me, i'm not alone.

from the very low info we see at said github repo, we understand that the vulnerability is at /api/liferay which is NOT present in 6.0.2, nor on the filesystem neither on configuration as route.

testing a more recent version, i saw that 6.1 branch actually has /api/liferay but by default it's limited to "localhost".
it could be possible to open it to more IPs of course, but i don't see it happen so frequently to have a 0.0.0.0 as trusted host.

i think this vulnerability doesn't affect 6.0 branch, it *could* affect 6.1 branch but not on default configuration.
plus, it's not yet clear if this is pre-auth or post-auth.
i'll dig newer branches as soon as i can.


p.s.: exploitability is rated against a possible 6.1, and the fact that ysoserial makes java deserialization quite easy.

[1] https://github.com/chakadev/Liferay-CE-Portal-Java-Deserialization


20200329 edit:
lowering value, adding required auth
