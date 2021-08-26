---
layout: page
sidebar:
  nav: sidebar-ctf
aside:
  toc: False
---

An overview of CTFs I participated in during 2021 can be found [here](./overview-2021.html).

Check out the [Archive](/archive.html) to filter by tags!

<br>


<h2>Recent Write-ups</h2>

<ul>
  {% for post in site.posts limit:4 %}
    {% if post.hidden_tags contains "write-up" %}
      <li>
        <a href="{{ post.url }}">{{ post.title }}</a>
        {{ post.excerpt }}
      </li>
    {% endif %}
  {% endfor %}
</ul>

<br>

<h2>My Challenges</h2>

<ul>
  {% for post in site.posts %}
    {% if post.hidden_tags contains "challenge" %}
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

