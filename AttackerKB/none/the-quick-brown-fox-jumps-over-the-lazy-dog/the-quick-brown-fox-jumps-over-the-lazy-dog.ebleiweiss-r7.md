---
title: the quick brown fox jumps over the lazy dog
author: ebleiweiss-r7
score: 1
topic_attacker_value: 2
topic_exploitability: 0
created: '2019-11-13T17:01:44.625368'
revision_date: '2020-02-13T17:11:57.121667'
assessment_id: a4c3bb59-0b35-40c1-9c83-153253dc413b
topic_id: 9587f826-d6ea-46ae-9c51-642ac5894dad
topic_short_id: ye54ewLvPp
topic_slug: the-quick-brown-fox-jumps-over-the-lazy-dog
akb_topic_url: https://attackerkb.com/topics/ye54ewLvPp/the-quick-brown-fox-jumps-over-the-lazy-dog
akb_assessment_url: https://attackerkb.com/topics/ye54ewLvPp/the-quick-brown-fox-jumps-over-the-lazy-dog#a4c3bb59-0b35-40c1-9c83-153253dc413b
author_ratings:
  attacker-value: 2
  confidence-in-ratings: 3
  effort-to-develop-exploit: 4
  mitigation-strength: 4
  reliability: 2
  stability: 4
  used-successfully: 4
---

# the quick brown fox jumps over the lazy dog

*Assessment by ebleiweiss-r7, archived from [AttackerKB](https://attackerkb.com/topics/ye54ewLvPp/the-quick-brown-fox-jumps-over-the-lazy-dog#a4c3bb59-0b35-40c1-9c83-153253dc413b).*

---

Watch _Jeopardy!_, Alex Trebek's fun TV quiz game.

```golang
// A cow will moo until it is being milked
func cow(num int, mootube chan Moo) {
    tube := make(chan bool)
    for {
        select {
        case mootube <- Moo{num, "moo", tube}:
            fmt.Println("Cow number", num, "mooed through the mootube")
            <-tube
            fmt.Println("Cow number", num, "is being milked and stops mooing")
            mootube <- Moo{num, "mooh", nil}
            fmt.Println("Cow number", num, "moos one last time in relief")
            return
        default:
            fmt.Println("Cow number", num, "mooed through the mootube and was ignored")
            time.Sleep(time.Duration(rand.Int31n(1000)) * time.Millisecond)
        }
    }
}
```
