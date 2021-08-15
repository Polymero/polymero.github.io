---
layout: page
sidebar:
  nav: sidebar-ctf
aside:
  toc: False
---

<h2>Recent Write-ups</h2>

<ul>
  {% for post in site.posts limit:3 %}
    {% if post.tags contains "Write-up" %}
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
    Debug4RMY CTF 2021 expected to be online sometime late 2021 or early 2022!
  {% endunless %}
</ul>

