---
title: kubectl cp path traversal
author: kevthehermit
score: 1
topic_attacker_value: 4
topic_exploitability: 1
topic_disclosure_date: '2019-04-01T14:29:00'
created: '2020-04-23T20:59:18.824266'
revision_date: '2020-04-23T20:59:18.828934'
assessment_id: 684b4e21-7b6e-40d7-93c7-e1c1cfca13bf
topic_id: c6953e35-2936-4a2e-b35b-226a4e42d556
topic_short_id: GrZ1kX5pt2
topic_slug: kubectl-cp-path-traversal
akb_topic_url: https://attackerkb.com/topics/GrZ1kX5pt2/kubectl-cp-path-traversal
akb_assessment_url: https://attackerkb.com/topics/GrZ1kX5pt2/kubectl-cp-path-traversal#684b4e21-7b6e-40d7-93c7-e1c1cfca13bf
author_ratings:
  attacker-value: 4
  exploitability: 1
  tags:
  - common_enterprise
  - high_privilege_access
  - difficult_to_develop
  - post_auth
---

# kubectl cp path traversal

*Assessment by kevthehermit, archived from [AttackerKB](https://attackerkb.com/topics/GrZ1kX5pt2/kubectl-cp-path-traversal#684b4e21-7b6e-40d7-93c7-e1c1cfca13bf).*

---

There are a lot of moving parts to be able to exploit this. But if successful will give an attacker a container escape on to the kube host. 
An attacker must already have shell access to a container and there must be a process running from the host that uses the kubectl cp command. 
This is *occasionally* seen used to copy files like log files out of a container to the host for backup or additional processing. 

If a user can replace the tar binary in the container it is possible to perform actions like editing the .bashrc file on the host. This could be used to create new SSH accounts, or establish a reverse shell as that user. Typically with root permissions. 
