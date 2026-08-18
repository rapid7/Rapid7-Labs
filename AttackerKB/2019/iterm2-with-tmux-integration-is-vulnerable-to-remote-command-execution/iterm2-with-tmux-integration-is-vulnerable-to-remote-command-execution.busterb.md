---
title: iTerm2 with tmux integration is vulnerable to remote command execution
author: busterb
score: 1
topic_attacker_value: 3
topic_exploitability: 1
topic_disclosure_date: '2019-10-09T20:15:00'
created: '2019-10-09T23:13:26.535497'
revision_date: '2020-02-13T17:12:01.118277'
assessment_id: 122bb0b0-7d8c-46b4-b47b-cd0794c605da
topic_id: 9efebe1b-7367-4d14-8ebe-cfc2fcf7be6f
topic_short_id: sjgL3nQfvx
topic_slug: iterm2-with-tmux-integration-is-vulnerable-to-remote-command-execution
akb_topic_url: https://attackerkb.com/topics/sjgL3nQfvx/iterm2-with-tmux-integration-is-vulnerable-to-remote-command-execution
akb_assessment_url: https://attackerkb.com/topics/sjgL3nQfvx/iterm2-with-tmux-integration-is-vulnerable-to-remote-command-execution#122bb0b0-7d8c-46b4-b47b-cd0794c605da
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 3
  effort-to-develop-exploit: 3
  exploitability: 1
  urgent-to-patch: 5
---

# iTerm2 with tmux integration is vulnerable to remote command execution

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/sjgL3nQfvx/iterm2-with-tmux-integration-is-vulnerable-to-remote-command-execution#122bb0b0-7d8c-46b4-b47b-cd0794c605da).*

---

It's probably just as important to choose terminal emulators that have minimal feature sets if you are doing administration work in the first place. iTerm2 in particular has a lot of features that are internally labeled as insecure, so it probably makes sense to evaluate if you are actually using those features and if you need them.

A maybe growing thread on exploitation: https://twitter.com/TheColonial/status/1182032288785166336

Also here's where to disable some of the other features by answering 'Yes' to this setting.

![image](https://user-images.githubusercontent.com/4108654/66527074-67f15380-eac0-11e9-8890-ed3b52daa119.png)
