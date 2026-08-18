---
title: Adobe Flash Overflow in ID3 Tag Parsing
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2015-08-14T01:59:00'
created: '2019-09-12T18:07:04.091118'
revision_date: '2020-02-13T17:12:21.762236'
assessment_id: 863e3f61-cbf6-44c1-aea8-ee28210bee64
topic_id: b8e7482a-6479-48ad-b973-1e03e92a01a6
topic_short_id: kEPE9YPti7
topic_slug: adobe-flash-overflow-in-id3-tag-parsing
akb_topic_url: https://attackerkb.com/topics/kEPE9YPti7/adobe-flash-overflow-in-id3-tag-parsing
akb_assessment_url: https://attackerkb.com/topics/kEPE9YPti7/adobe-flash-overflow-in-id3-tag-parsing#863e3f61-cbf6-44c1-aea8-ee28210bee64
---

# Adobe Flash Overflow in ID3 Tag Parsing

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/kEPE9YPti7/adobe-flash-overflow-in-id3-tag-parsing#863e3f61-cbf6-44c1-aea8-ee28210bee64).*

---

## Details

The decode_buffer_size is calculated this way in Flash:

```c
decode_buffer_size = (encode_data_size – 1) * 6 + 2
```

In asm:

```
.text:10024F13 loc_10024F13:                           ; CODE XREF: sub_10024C79+278j
.text:10024F13                 mov     eax, ebx
.text:10024F15                 imul    eax, 6
.text:10024F18                 add     eax, 2
.text:10024F1B                 cmp     [esi+28h], eax
.text:10024F1E                 mov     [ebp+var_20], eax
.text:10024F21                 jge     short loc_10024F4D
```

During decoding, the buffer can be reallocated:

```c
int current_buffer_size

int decoded_buffer_size

if (current_buffer_size  < decoded_buffer_size) {

// reallocate the decode buffer

}
```

If the encode_data_size is larger than 0x2aaaaaab, it will cause an integer overflow in the
calculation of ```(encode_data_size –1) * 6 + 2```

## Patch for CVE-2015-5560

Version 18.0.0.232:

```
.text:10024E3E                 mov     eax, [ebp+var_14]
.text:10024E41                 imul    eax, 6
.text:10024E44                 inc     eax
.text:10024E45                 inc     eax
.text:10024E46                 cmp     eax, [ebp+var_14]
.text:10024E49                 jbe     loc_10024FB8
```

```
(encode_data_size * 6 + 2) >  encode_data_size
```

Note that it seems this patch can be bypassed, see CVE-2015-8446
