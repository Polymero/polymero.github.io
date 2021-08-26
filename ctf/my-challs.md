---
layout: page
sidebar:
  nav: sidebar-ctf
aside:
  toc: False
---

<h2>My Challenges</h2>

I love to make creative and unique challenges that push the players to really think about and investigate potential vulnerabilities, instead of pulling a ready-made exploit from GitHub. 

I usually divide my challenges into one of three categories:

1. **TOY** challenges are all about analysing and exploiting vulnerabilities in toy cryptographic primitives I make myself. The players will attack these primitives directly. This will test a player's cryptographic knowledge and their ability to cryptanalyse using the provided source code.

2. **IMP** challenges are all about exploiting flaws in the implementation of secure cryptographic primitives. The players will attack the security of these primitives by abusing their flawed implementation. This will test a player's knowledge on the limitations of the used primitives and their ability to exploit these limitations.

3. **PZL** challenges are somewhat looser challenges that challenge the player's math, logic, and problem solving skills.

<br>

In need of Crypto challenges for your CTF? [Get in touch](https://www.sebven.com/about.html)!

<br>

### Overview

<ul>
  {% for post in site.posts %}
    {% if post.tags contains "Challenge" %}
      {% assign available = true %}
      <li>
        <a href="{{ post.url }}">{{ post.title }}</a>
        {{ post.excerpt }}
      </li>
    {% endif %}
  {% endfor %}
  {% unless available %}
    No challenges publicly available yet. <br>
    K3RN3LCTF 2021 expected to be online on the 29th and 30th of November!
  {% endunless %}
</ul>