---
title: "Hack, don't just audit"
date: 2024-10-22T22:21:00+03:00
draft: false
tags: 
- Hacking
- Security
- Code Review
- Auditing
---

![image](../../static/images/said-the-stars.jpg)

*“Look up.” Said the Stars “And all your dreams will reveal themselves.” - Yuumei*

Most new auditors and security researchers struggle to find unique vulnerabilities. Why? Simply put, they're auditors, not hackers. At the core, they're approaching the task with the wrong mindset.

Today's security education outside apprenticeships is essentially a spoon-feeding of known vulnerabilities. Students learn how vulnerabilities work and the patterns behind them, but not how to think about finding new ones. This creates what I call the "auditor cognitive bias" - a sort of mental checklist approach to security assessment.

Auditors typically examine code by following the "happy path," much like a unit test. They assess functionality, figuring out how code works and if it works at all, while pattern-matching for known issues based on their training and experience. We call these heuristics. 

This approach is crucial but falls short in uncovering novel or complex vulnerabilities. Over time, if not guided, our brains will fall into routine ways of thinking or habits. We may subconsciously only rely on these heuristics for a particular code pattern that is familiar to us, falsely believing it is secure due to similar code encountered prior. 

We should approach every component like it is new to us with the methodology detailed below. Even when code is the same, the context isn't. You should question everything, even battle tested libraries can introduce vulnerabilities.

Additional note:

Some people even straight up use an actual checklist like the [SCSVS](https://github.com/ComposableSecurity/SCSVS) or [solcurity](https://github.com/transmissions11/solcurity). Those are the worst offenders because relying on an actual checklist over heuristics adds overhead and uses up energy that is better spent on finding unique bugs. Leave the checklist to the developers.

#### The Hacker's Approach

To level up, you need to think in invariants alongside your heuristics. What does that mean? Identify properties that must hold true based on the developers' intentions, then reason about how those could be broken. This could be due to a mismatch between intentions and the actual implementation.

Approach the code like you're interrogating it. Don't just figure out how it works and pattern match - question why it works, what assumptions it's making, and how they could be broken. This ensures you don't fall victim to your cognitive biases.

Don't forget about upstream dependencies and integrations. That's where the fun stuff happens - misconfigurations, desyncs in how pieces fit together. Any time there is an interaction with an external contract, there is a good chance a mistake was made. It's a goldmine for functionality mismatches.

Hacking is about finding clever ways to bypass rules. Looking at said rules and asking why you can't do X, how said rule is enforced and then finding a way to do X anyway bypassing the enforcement.

In many ways, it's about being a rebel. Rebelling against the machine, the code's law. Sorry, I'm getting borderline religious here :D

#### Case Study: The Poly Network Hack

A perfect example of this in practice is the Poly Network hack. It's still a favourite exploit of mine because of it's ingenuity. I'd write a poem about it if I could but in short, it's the very epitome of what I believe a hack is. 

The TL;DR is the registry that contained the private keys holding the network's funds had a function to update them. It was locked behind privileged `onlyOwner()` access. Now, usually, a lot of people would assume that means it's secure and move on, maybe make a suggestion for it to be two step or multi-sig, fearing centralisation.

So how did the black hat get around this privilege? How did they escalate their privileges? (heh)
They didn't trust how access control was handled. If it was an EOA as owner, that would be wraps unless they spear phished the key holder. If it was a contract though...perhaps there was an exposed function somewhere. 

So they looked into it and voila, the owner was indeed another contract and with a conveniently exposed function that let you call any function on ANY contract if it matched the following function sig:

![image](https://hackmd.io/_uploads/B1iZzxB5R.png)

All that was left was forging an input that matched the target func sig. Something trivial with a script, given that only the first four bytes were needed and not the entire hash.

As hackers, our goal is to grok a system, challenge the assumptions it presents and try to trick it into doing what it wasn't intended to, not to simply go through a checklist. Some may argue that the hacker approach lacks comprehensiveness but if you do it right, it's even more comprehensive than anything else out there when it comes to manual review.

#### Recap

1. Grok the system fully, diving into any and all parts. As an example, don't shy away from inline assembly.
2. Find the code's assumptions/invariants and try to break them.
3. Trusting abstractions is the mind killer. Developers trust abstractions and trust YOU to verify them.
4. Don't assume dependencies and integrations are secure or done right.

#### Parting Advice

Always approach code thinking there's an issue waiting for you. Remember, developers are human and make mistakes. Go in with the mindset that you're at least on their level of proficiency. Ignore thoughts like "it's too hard" or "I'm not smart enough for this." Challenge yourself, keep learning, and never give up. The results will be worth it.

Don't be a lamer. Be a hacker.

**Acknowledgements**

- [DevTooligan](https://x.com/devtooligan/) - For reading through my drafts, proof reading, providing excellent feedback that cannot be understated, even a few edits.
- [jtriley](https://x.com/jtriley_eth) - For proof reading this article and providing suggestions. :)
