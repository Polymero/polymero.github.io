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

<br><br>


<h2>Overview of Published Challenges</h2>

<h3>Crypto</h3>

| Challenge | Framework | Published | Primitive | Type | Diff | Solves |
| --------- | --------- | --------- | --------- | ---- | ---- | ------ |
| [Twizzty Buzzinezz](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-Twizzty-Buzzinezz.html) | Honeycomb | K3RN3LCTF 2021 | XOR | TOY | 1 | 116 |
| [Non-Square Freedom 1](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-Non-Square-Freedom.html) | Prime Crimes | K3RN3LCTF 2021 | RSA | TOY | 1 | 21 |
| [1-800-758-6237](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-1-800-758-6237.html) | 16-byte Nightmares | K3RN3LCTF 2021 | AES-CTR | IMP | 2 | 28 |
| [Poly-Proof](https://www.sebven.com/ctf/2021/11/16/K3RN3LCTF2021-Poly-Proof.html) | Zero-Effort-Proof | K3RN3LCTF 2021 | PCS | TOY | 2 | 11 |
| [Poly Expo go BRRRRR](https://www.sebven.com/ctf/2021/11/16/K3RN3LCTF2021-Poly-Expo-go-BRRRRR.html) | Prime Crimes | K3RN3LCTF 2021 | RSA | TOY | 3 | 9 |
| [Cozzmic Dizzcovery](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-Cozzmic-Dizzcovery.html) | Honeycomb | K3RN3LCTF 2021 | XOR | PZL | 4 | 3 |
| [Non-Square Freedom 2](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-Non-Square-Freedom.html) | Prime Crimes | K3RN3LCTF 2021 | RSA | TOY | 4 | 11 |
| [Ain't no Mountain High Enough](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-Aint-no-Mountain-High_Enough.html) | Mountain Cipher | K3RN3LCTF 2021 | Hill Cipher | TOY | 5 | 1 |
| [Objection!](https://www.sebven.com/ctf/2021/11/14/K3RN3LCTF2021-Objection.html) | Prime Crimes | K3RN3LCTF 2021 | DSA | IMP | 6 | 2 |
| [Tick Tock]() | Erratic Elliptics | K3RN3LCTF 2021 | Group Theory | TOY | 6 | 6 |
| [Beecryption](https://www.sebven.com/ctf/2021/11/16/K3RN3LCTF2021-Beecryption.html) | Honeycomb | K3RN3LCTF 2021 | Linear | TOY | 7 | 2 |
| [Shrine of the Sweating Buddha]() | Sweating Buddha | K3RN3LCTF 2021 | Paillier | TOY | 8 | 0 |
| [Mowhock]() | Submit to Chaos | K3RN3LCTF 2021 | Logistic Map | TOY | 8 | 0 |
| [Game of Secrets]() | Cellular Mania | K3RN3LCTF 2021 | Game of Life | TOY | 8 | 2 |
| [Total Encryption]() | Remote Secure Armoury | K3RN3LCTF 2021 | RSA | IMP | 9 | 0 |
| [HADIOR]() | Spinning my Web | K3RN3LCTF 2021 | DSA | TOY | 9 | 3 |
| [Beastly Vault]() | Spinning my Web | @HackCTF 2021 | AES | IMP | 9 | ? |
{:.custom-table}

<h3>Reverse Engineering</h3>

| Challenge | Framework | Published | Primitive | Type | Diff | Solves |
| --------- | --------- | --------- | --------- | ---- | ---- | ------ |
| [lightningrod](https://www.sebven.com/ctf/2021/11/16/K3RN3LCTF2021-lightningrod.html) | Superweapons | K3RN3LCTF 2021 | XOR | REV | 4 | 3 |
| [WannaSwirl](https://github.com/Kasimir123/CTFWriteUps/tree/main/2021-11-K3RN3LCTF/WannaSwirl) (Co-Author) | WannaSwirl | K3RN3LCTF 2021 | Malware | REV | 7 | ? |
{:.custom-table}

<h3>Misc</h3>

| Challenge | Framework | Published | Primitive | Type | Diff | Solves |
| --------- | --------- | --------- | --------- | ---- | ---- | ------ |
| [3Dangerous Commute]() | Hyperspatial Engineering | K3RN3LCTF 2021 | Maze | PZL | 5 | 5 |
{:.custom-table}
<br><br>


### Recent Posts

<ul>
  {% for post in site.posts %}
    {% if post.hidden_tags contains "my-challenge" %}
      {% assign available = true %}
      <li>
        <a href="{{ post.url }}">{{ post.title }}</a>
        {{ post.excerpt }}
      </li>
    {% endif %}
  {% endfor %}
  {% unless available %}
    No challenges publicly available yet.
  {% endunless %}
</ul>