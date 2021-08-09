---
title: UIUCTF 2021 - Constructive Criticism
category: CTF
tags: Write-up Misc Signal-processing Audio
excerpt_separator: <!--more-->
---

Misc -- 408 pts (14 solves) -- Chall author: Pranav Goel

Some lo-fi bops on Soundcloud seem to be hiding something. There are cuts in the song where the emphasis jumps from one stereo-channel to the other. Turns out the separate channels in the WAV files are not exactly the same. At some parts they align, and at others they are slightly different. Visualising this difference reveals a bit-like structure which we decode in order to obtain the flag! A unique challenge for sure!

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/ConstructiveCriticism_chall.png)

Upon visiting this aspiring Soundcloud artist's playlist, we find 20 songs all seemingly only playing on the right stereo-channel. Yuck! Luckily, once the songs are downloaded it seems they play properly after all. But wait, what's that? It sounds as if there are some cuts in there where the emphasis suddenly shifts from the lift stereo-channel to the right and vice versa. Interesting... Let's buy a one-way-ticket to Audacity.

![](/assets/ctf/CC_waveform.png)

Three channels? This seems a bit fishy, let's take a closer look at the waveforms in Python. More specifically, I overlaid the first two channels to see if they would match up and it appears they are not quite the same.

```py
from scipy.io import wavfile
import matplotlib.pyplot as plt

samplerate, data = wavfile.read('.Tracks/Ambulo X Kasper Lindmark – Pleasant_track_1.wav')

stream_1, stream_2, stream_3 = list(zip(*data))

plt.figure(figsize=(32,8))
plt.plot(stream_1,lw=1,alpha=1)
plt.plot(stream_2,lw=1,alpha=.9)
plt.show()
```

![](/assets/ctf/CC_stream12.png)

"The waveforms Mason, what do they mean?!?"


## Exploitation

Turns out there are certain parts of the song where these two streams do and do not align. Yes, and no. '0', and '1'. BITS! I see bits! Let's try to fish out the difference between the two streams by assigning a '1' bit to every significant difference between the two channels. _For visual aid, I have divided the plot into 24 sections to highlight the bit structure._

```py
bits = [0 if abs(stream_1[i] - stream_2[i]) < 1 else 1 for i in range(0, len(data), 100)]

plt.figure(figsize=(32,4))
plt.scatter(range(len(bits)), bits, s=0.5)

for i in range(24):
    plt.axvline(len(stream_1)//24//100*(i+1), c='black', alpha=0.3)

plt.show()
```

![](/assets/ctf/CC_bitstream.png)

If we translate these bits to bytes we read something familiar...

```py
long_to_bytes(int('011101010110100101110101',2))

b'uiu'
```

It is the start of the flag wrapper! However, let's not do all of this by hand and just bash together a Python script to do it for us. Note that in the final file the bit spacing was a factor of two smaller.

```py
track_list = """
Ambulo X Kasper Lindmark – Pleasant_track_1.wav
BVG X Møndberg – Insomnia_track_2.wav
Bcalm X Banks – Because_track_3.wav
Dontcry X Glimlip X Sleepermane - Jiro Dreams_track_4.wav
Flovry X Tender Spring - First Heartbreak_track_5.wav
Hoogway – Everything (You Are)_track_6.wav
Ky Akasha – Memory Within A Dream_track_7.wav
Loafy Building X Hoffy Beats – Sleepless Wonder_track_8.wav
Mila Coolness – Far Away_track_9.wav
Miramare X Clément Matrat – Foam_track_10.wav
S N U G – Dreams Of You_track_11.wav
Softy X Kaspa_track_12.wav
Tenno – Daydreaming_track_13.wav
WYS – Snowman_track_14.wav
brillion_track_15.wav
brillion_track_16.wav
Drkmnd - Satellite Nights_track_17.wav
less_track_18.wav
No One's Perfect X Kanisan – Gentle Wind_track_19.wav
Tysu X Spencer Hunt – Rainy Day_track_20.wav
""".split('\n')[1:-1]

flag = b""
for track in track_list:
    
    print('Working on track', track_list.index(track), 'Flag progress:', flag, end='\r', flush=True)
    
    samplerate, data = wavfile.read('C:/Users/Nika/Downloads/Tracks/'+track)
    
    stream_1, stream_2, stream_3 = list(zip(*data))
    bits = [0 if abs(stream_1[i]-stream_2[i]) < 1 else 1 for i in range(len(data))]
    
    if track == "Tysu X Spencer Hunt – Rainy Day_track_20.wav":
        step = len(bits) // 24 // 2
    else:
        step = len(bits) // 24
        
    flag += long_to_bytes(int(''.join([str(int(sum(bits[i:i+step]) > step // 2)) for i in range(0,len(bits),step)]),2))

print('\n' + flag.encode())
```

After some running the code neatly returns our flag! ^w^

Too slow for your liking? A smaller sample size in creating the 'bits' list might speed things up, although a pre-sampling of the 'data' might prove more efficient as most of the time goes to the 'zip(\*data)' part.

Ta-da!
```
uiuctf{lofi_bops_but_encrypting_audio_using_interference_slaps}
```
