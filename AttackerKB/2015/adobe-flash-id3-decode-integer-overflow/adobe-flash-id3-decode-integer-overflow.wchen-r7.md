---
title: Adobe Flash ID3 Decode Integer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2015-12-10T06:00:00'
created: '2019-09-12T18:07:24.826588'
revision_date: '2020-02-13T17:12:16.554552'
assessment_id: ee091db4-678c-4312-84ae-93fd32302bfa
topic_id: 49bfa54b-5c07-4f82-a637-56b655bc873a
topic_short_id: yt1cCYwLtZ
topic_slug: adobe-flash-id3-decode-integer-overflow
akb_topic_url: https://attackerkb.com/topics/yt1cCYwLtZ/adobe-flash-id3-decode-integer-overflow
akb_assessment_url: https://attackerkb.com/topics/yt1cCYwLtZ/adobe-flash-id3-decode-integer-overflow#ee091db4-678c-4312-84ae-93fd32302bfa
---

# Adobe Flash ID3 Decode Integer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/yt1cCYwLtZ/adobe-flash-id3-decode-integer-overflow#ee091db4-678c-4312-84ae-93fd32302bfa).*

---

## Details

This is a vulnerability in Adobe Flash. It is due to an incomplete patch of CVE-2015-5560. The decode_buffer_size is calculated this way in Flash:

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

## Analysis of CVE-2015-8446

If the patch is bypassed, we have CVE-2015-8446.

If ```encode_data_size``` is 0x15555580:

```
(0x15555580 – 1) * 6 + 2 = 0x800000FC
```

Which is less than 0.

And then that can cause an overflow.

## ByteArray Length Protection

Adobe introduced the ByteArray Length Protection in December, which would make exploitation
difficult against newer versions of Adobe Flash.

It is likely the exploit in the wild exploited an older version of Adobe Flash (this needs to be
confirmed).
