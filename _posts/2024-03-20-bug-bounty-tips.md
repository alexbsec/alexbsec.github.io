---
title: Bug Bounty Tips
published: true
---

Hi folks! It's been a while, hasn't it?

First and foremost, I've not been that active here these past two months because I decided to focus myself on Bug Bounties rather than CTFs, at least for now. Differently from CTFs, I cannot disclose every Bug I find on Bug Bounties, so that's why the blog has been a bit quiet. For that, I'm sorry! However, don't go thinking I'm never going to post anymore! In fact, there are some CVEs on the way that I intend on posting, and even some snippets on what I've been up to.

Transitioning to our main topic today, I realize that my shift towards Bug Bounties has sparked curiosity and raised questions among many of you. Lately, I've been inundated with messages on LinkedIn, with many of you asking, _"Hey! How did you start doing bug bounties? Can you help me?"_ or expressing concerns like, _"I'm starting out hunting but have not found anything so far. Should I give up?"_

Given the volume of inquiries and the impracticality of responding to each one individually, I've decided to dedicate this post to shedding light on my journey into Bug Bounties. 

# The beginning

Thinking back a little, I recall the first time I heard about Bug Bounties was during my high school years. Of course, that wasn't when I actually started participating in them, but it's always insightful to trace back to our initial encounters with anything. It was only on 2022 I decided to shift my career from being a Physicist into a Cybersecurity enthusiast and Bug Hunter. The reason behind that? This is a topic for another post!

My very first foray into participating in a Bug Bounty Program was through HackerOne, which, for those who might not be familiar, stands as one of the most prestigious Bug Bounty platforms in the cyber realm. I took my inaugural plunge with a bank (whose name escapes me now), where I stumbled upon what I believed was an open redirect and eagerly reported it. Truth be told, at that time, my skills were quite nascent, and my report was swiftly closed due to lack of impact.

This initial and rather significant rejection came in August 2022, prompting me to take a step back and reassess my stance on the chessboard. It became clear that I wasn't yet equipped to dive into such programs, especially one associated with a bank — the one niche that might be reputed with the best security standards. Because of that, I began to diligently build my skills from scratch.

## The material

Like many newcomers to the cybersecurity scene, I found myself swamped by an avalanche of information about the field. I encountered numerous paid online courses, for which I regretfully shelled out money, only to learn nothing — either due to the courses being scams or simply lacking in effective teaching methods. Yet, not everything was in vain, as among these attempts, I discovered the renowned online web hacking practice lab, [Portswigger](https://portswigger.net)!

If this is unfamiliar to you, picture Portswigger as a website that invites you to hack into it, without any risk of harm or legal repercussions. It's crafted to mimic a wide array of web vulnerabilities and the techniques to exploit them, making it an incredibly user-friendly platform. Plus, it boasts a vast community, ensuring that if you ever find yourself puzzled by one of their labs, help is readily available online. Can't recommend it enough. Nowadays, it even includes learning sections, allowing you to grasp the concepts before getting your hands dirty.

I decided to complete at least all beginner level labs before coming back to Bug Bounties. And that's what I did! Of course, at first I could only solve the labs with a solution sitting right beside me. So my strategy was the following:

<div style="display: flex; justify-content: center; align-items: center;">
<img src="../assets/bbounty-mermaid.png" alt="flow chart">
</div>

To be honest, this strategy is the one I use to this day whenever I want to solve something I can't without a solution. 

## The comeback

After completing all the easy level labs, I decided to return to hunting. That's when I discovered my first ever vulnerability. And guess where I found it? On Portswigger's own website! However, it wasn't in the labs; I identified an actual vulnerability within their website. Funny enough, it was another open redirect. This time, however, I paused to consider: how could I report this and demonstrate its impact effectively? My initial attempt had been rejected due to a lack of demonstrated impact. This is the moment you often hear hackers mention the importance of thinking outside the box. So after some days I found a way to showcase how one could leverage that into information disclosure via an SSRF (Server Side Request Forgery) and decided to report it.

I wrote an e-mail to their support team and... You guessed it right! The next day they got it solved and fixed!

# The grind

I'd strongly recommend to all you readers: practice makes perfect. I've always been a curious person, so I discovered a variety of websites offering cybersecurity labs for practice. [Pwnable](https://pwnable.kr) is one such example, and so is [Root-me](https://www.root-me.org). The former is particularly challenging, as solutions are not readily available online, and many of their challenges involve binary exploitation, system privilege escalation, and reverse engineering — concepts not covered by Portswigger, for instance. Root-me is another excellent resource that offers a wide range of labs, from binary to web exploitation, though solutions are even more scarce than on Pwnable.

I also recommend [Hacker101](https://www.hacker101.com/), HackerOne's own practice lab website. It is great because as you solve them you earn points. With enough points, you can be called to a private program, where the competition is way smaller. This is what actually happened to me. After solving a bunch of these, I got called to check Latam Airlines and Sephora's VDP programs. I could report one or two vulns there as well, but nothing too impactful.

Finally, I must mention [TryHackMe](https://tryhackme.com/) and [HackTheBox](https://www.hackthebox.com/) as one of the best learning resources out there. They have excellent study material and amazing labs to be solved, ranging from super easy ones up to almost impossible Dark Souls like ones.

## Bug Bounty Platforms

When it comes to choosing platforms, I strongly suggest opting for less competitive ones to avoid feeling overwhelmed and frustrated by reporting duplicates or not finding any vulnerabilities. My approach is always consistent: I select a program that appeals to me both in terms of potential earnings and features, then dedicate at least 15 days to thorough research and reconnaissance before starting another 15 days of testing. If I don't find anything during this time, I move on to another program. The lack of findings could be due to a lack of motivation or excessive competition. You never know. By allocating time to understand the program and get a feel for it, you can confidently decide whether you're on the right track. HackerOne and [Bugcrowd](https://www.bugcrowd.com/) are well-known platforms, which might be advantageous in terms of payouts but can sometimes be too competitive, leading to fewer vulnerabilities found.

I might be spoiling it, but I strongly recommed you take a look at [Yogosha](https://yogosha.com); it's a platform that requires you to sign up to participate, complete a CTF, and pass. If you pass, they grant you access, and the competition is much lower than on other big platforms like HackerOne and Bugcrowd. You might also want to check out [HuntrDev](https://huntr.dev). This platform is focused on finding bugs in machine learning projects and usually involves code review, which makes things a bit easier. As an honorable mention, if you'd like to get paid in euros, you can check [Intigriti](https://www.intigriti.com/) Bug Bounty Platform. It offers a good balance between competitiveness and payouts.

## Vulns found

I found a wide range of vulnerabilities, some by myself, others colabing with friends. Among the most critical findings were a Remote Code Execution (RCE) vulnerability in an open-source project, a SQL injection that led to a database dump, and session hijacking facilitated by stolen cookies. I never concentrate on the low-hanging fruits; instead, my strategy is to always look for ways to pivot and amplify the impact of my findings.

## Methodology

Everyone develops their own methodology for bug hunting. Personally, I prefer manual exploitation because it has yielded the best results for me. Manual methods allow for a deeper understanding of vulnerabilities and their nuances. While I've observed others successfully employ automation — and it does have its benefits, especially for covering a broader surface area quickly — it ultimately boils down to what strategy resonates most with your style of hunting. Finding the approach that best represents your way of thinking and exploring is what will make you see results.

# Conclusion

In wrapping up, here are my parting words of wisdom: once you've gotten a handle on a specific vulnerability, dedicate yourself to the reconnaissance and research phase. I cannot stress enough how this is important, as a deep understanding of your target can significantly streamline the exploitation process. Launching into attempts without a clear strategy or understanding seldom yields fruitful results. Prioritize reconnaissance, and keep your spirits high—even if you don't strike gold within the first 15 days or even a month. My own experience has seen peaks of discovering multiple vulnerabilities within a single week, contrasted with dry spells stretching over months.

And, if there's one piece of advice to highlight above all, it's the importance of persistence. Commit to spending at least 10 to 15 days on reconnaissance and testing straightforward tasks on your target. This dedicated period of exploration and understanding lays the groundwork for more effectively identifying and connecting vulnerabilities. Remember, mastering the art of bug hunting is a marathon, not a sprint. Resilience in the face of challenges and patience in your process are your greatest allies.

And what about your experience? DM me with yours and we might even be able to colab!

I wish you all happy hacking!

And as always, don't forget to do your **research**!


<a href="/">Go back</a>

