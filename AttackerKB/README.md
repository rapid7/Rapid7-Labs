# AttackerKB assessment archive

A frozen snapshot of community vulnerability assessments from
[AttackerKB](https://attackerkb.com), published here as Markdown.

**This is a frozen snapshot which won't be updated.** AttackerKB is
[being sunset](https://www.rapid7.com/blog/post/ve-sunsetting-public-attackerkb-platform/) and the public platform closes on
2026-08-18; these files are the durable public record of the assessment
archive. Nothing further will be added and the assessments won't be revised, so
read each one as a dated artefact: the ratings and the exploitability judgements
are fixed at the point its author wrote them. Links back to
`attackerkb.com` are preserved for provenance but will stop resolving once the
site is retired. Where an assessment's own text links to another AttackerKB
topic or assessment, the original link is left as the author wrote it and an
`[archive]` link to the archived copy is added beside it.

## Contents

1882 assessments across 1525 vulnerability topics. A topic can carry
several assessments, each written by a different contributor, so there is one
file per *assessment* rather than per topic.

| Directory | Assessments |
| --- | --- |
| `2003/` | 1 |
| `2005/` | 1 |
| `2006/` | 1 |
| `2007/` | 1 |
| `2008/` | 1 |
| `2009/` | 3 |
| `2010/` | 2 |
| `2011/` | 5 |
| `2012/` | 18 |
| `2013/` | 22 |
| `2014/` | 28 |
| `2015/` | 44 |
| `2016/` | 24 |
| `2017/` | 49 |
| `2018/` | 63 |
| `2019/` | 235 |
| `2020/` | 417 |
| `2021/` | 287 |
| `2022/` | 140 |
| `2023/` | 180 |
| `2024/` | 153 |
| `2025/` | 92 |
| `2026/` | 21 |
| `none/` | 94 |

See [INDEX.md](INDEX.md) for the full list.

## Layout

```
AttackerKB/{year}/{topic}/{topic}.{author}.md
```

- **year** is the CVE year where the topic names a CVE, otherwise the year of
  the topic's AttackerKB disclosure date. `none/` holds topics
  with neither.
- **topic** is the AttackerKB topic slug. Where the slug names a CVE, the CVE is
  moved to the front so each year's listing sorts by CVE id; the rest of the
  slug keeps its original wording and order. Where two distinct topics share a
  slug, the AttackerKB short id is appended to tell them apart.
- **author** is the contributor's AttackerKB username.

## Front matter

Each file carries YAML front matter with the contributor's own ratings
(`author_ratings`), the topic-level aggregate ratings (`topic_*`), and the
identifiers needed to join a file back to its source record: `assessment_id`,
`topic_id`, `topic_short_id`, `topic_slug`, and the original AttackerKB URLs.
Fields absent in the source are omitted rather than written as null.

## Scope and fidelity

Assessment prose is reproduced from the source records with one modification,
applied mechanically to every file: **an `[archive]` link is added**
beside each `attackerkb.com` URL, pointing at the archived copy of whatever that
URL referred to. The original URL is left exactly as written. Links in code
blocks are not annotated, since Markdown does not render links there, and
neither are links to topics that had no published assessments and so are not in
this archive.

Email addresses written into the prose by contributors or by advisories they
quoted are left as published. They are mostly part of the technical content
rather than contact details: the `emailAddress` field of a certificate's issuer
DN, a row of a dumped user table, a value in a captured request, a code-signing
identity. Removing them would damage the artefact, and all of it was rendered on
AttackerKB for years.

Nothing else is added, removed or reworded. Some assessments contain
proof-of-concept code, exploitation detail, or rough formatting; that is the
original content, not a rendering artefact.

Only assessments that were approved and not deleted in AttackerKB are included.
Contributor identity is limited to the public AttackerKB username; no contact
details or other contributor fields were exported.
