---
title: Dell Foundation Services installs root certificate and private key (eDellRoot)
author: asoto-r7
score: 1
topic_attacker_value: 5
topic_exploitability: 3
created: '2019-07-24T20:09:07.525941'
revision_date: '2020-02-13T17:12:30.254625'
assessment_id: 37b11c24-0469-4873-b98b-d78c1b3db6a4
topic_id: 75d27812-f60e-4f57-a96a-929bbc231185
topic_short_id: 5WoFEgM51m
topic_slug: dell-foundation-services-installs-root-certificate-and-private-key-edellroot
akb_topic_url: https://attackerkb.com/topics/5WoFEgM51m/dell-foundation-services-installs-root-certificate-and-private-key-edellroot
akb_assessment_url: https://attackerkb.com/topics/5WoFEgM51m/dell-foundation-services-installs-root-certificate-and-private-key-edellroot#37b11c24-0469-4873-b98b-d78c1b3db6a4
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 4
  effort-to-develop-exploit: 2
  exploitability: 3
  urgent-to-patch: 5
  used-successfully: 1
---

# Dell Foundation Services installs root certificate and private key (eDellRoot)

*Assessment by asoto-r7, archived from [AttackerKB](https://attackerkb.com/topics/5WoFEgM51m/dell-foundation-services-installs-root-certificate-and-private-key-edellroot#37b11c24-0469-4873-b98b-d78c1b3db6a4).*

---

It's terrifying that this certificate supports all issuance and application policies.  Reddit users have proven that this can be used to MitM HTTPS-encrypted web browsing, as well as to sign code.  It's unclear as to whether the certificate is unique to each install (which would turn this into maybe a local privesc, or whether the certificate is shared across all installs, at which point this becomes a threat to any Dell user on a compromised network.

It's also worth pointing out that some users didn't have the certificate described, but then had it added later after running updates.  So sysadmins might have checked for this, but then had their workstations put into a vulnerable state afterwards.
