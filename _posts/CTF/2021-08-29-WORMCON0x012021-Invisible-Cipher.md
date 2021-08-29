---
title: WORMCON 0x01 2021 - Invisible Cipher
category: CTF
tags: crypto substitution
hidden_tags: write-up
excerpt_separator: <!--more-->
---

Cryptography -- 419 pts (10 solves) -- Chall author: BUILDYOURCTF

Simple substitution cipher that can be assessed through frequency analysis. Or for the more busy ('lazy') people under us, a combination of quick frequency analysis and Quipqiup will do the trick just fine!

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/Invisible_Cipher_chall.png)

Classic 'simple' substitution ey, well let's take a look at what we've got.

```py
from numpy import unique

txt = "ぃ〷〴ぁ〴おう〰あお〾〽〲〴お〰お〺〸〽〶お〾〵おあ〲〾ぃ〻〰〽〳おう〷〾あ〴お〽〰〼〴おう〰あおぁ〾〱〴ぁぃお〱ぁい〲〴お〷〴お〷〰〳お〽〴〴〳おぃ〾お〱〴お〱〾ぃ〷お〱ぁ〰ぅ〴お〰〽〳おう〸あ〴お〵〾ぁおぃ〷〴おぃ〸〼〴あお〸〽おう〷〸〲〷お〷〴お〻〸ぅ〴〳おう〴ぁ〴おう〸〻〳お〰〽〳おぁい〳〴おぃ〷〴お〺〸〽〶お〾〵お〴〽〶〻〰〽〳おう〰あお〰ぃおう〰ぁおう〸ぃ〷お〷〸〼お〰〽〳お〷〰〳お〻〴〳お〰お〶ぁ〴〰ぃお〰ぁ〼えお〸〽ぃ〾おあ〲〾ぃ〻〰〽〳おぃ〾お〳ぁ〸ぅ〴お〷〸〼お〾いぃお〾〵おぃ〷〴お〻〰〽〳お〱〰ぃぃ〻〴お〰〵ぃ〴ぁお〱〰ぃぃ〻〴お〷〰〳お〱〴〴〽お〵〾い〶〷ぃおあ〸ぇおぃ〸〼〴あお〷〰〳お〱ぁい〲〴お〻〴〳お〷〸あお〱ぁ〰ぅ〴お〻〸ぃぃ〻〴お〰ぁ〼えお〰〶〰〸〽あぃお〷〸あお〵〾〴あお〰〽〳おあ〸ぇおぃ〸〼〴あお〷〰〳お〷〸あお〼〴〽お〱〴〴〽お〱〴〰ぃ〴〽お〰〽〳お〳ぁ〸ぅ〴〽お〸〽ぃ〾お〵〻〸〶〷ぃお〰ぃお〻〰あぃお〷〸あお〰ぁ〼えおう〰あおあ〲〰ぃぃ〴ぁ〴〳お〰〽〳お〷〴おう〰あお〵〾ぁ〲〴〳おぃ〾お〷〸〳〴お〷〸〼あ〴〻〵お〸〽おぃ〷〴おう〾〾〳あお〰〽〳お〸〽お〻〾〽〴〻えお〿〻〰〲〴あお〰〼〾〽〶おぃ〷〴お〼〾い〽ぃ〰〸〽あお〾〽〴おぁ〰〸〽えお〳〰えお〱ぁい〲〴お〻〰えお〾〽おぃ〷〴お〶ぁ〾い〽〳おい〽〳〴ぁお〰おぁい〳〴おあ〷〴〳お〻〸あぃ〴〽〸〽〶おぃ〾おぃ〷〴お〿〰ぃぃ〴ぁお〾〵おぃ〷〴お〳ぁ〾〿あお〾〽おぃ〷〴おぁ〾〾〵お〰〱〾ぅ〴お〷〸〼お〷〴おう〰あおぃ〸ぁ〴〳お〰〽〳おあ〸〲〺お〰ぃお〷〴〰ぁぃお〰〽〳おぁ〴〰〳えおぃ〾お〶〸ぅ〴おい〿お〰〻〻お〷〾〿〴お〸ぃおあ〴〴〼〴〳おぃ〾お〷〸〼おぃ〷〰ぃおぃ〷〴ぁ〴おう〰あお〽〾おいあ〴お〵〾ぁお〷〸〼おぃ〾おぃぁえおぃ〾お〳〾お〰〽えぃ〷〸〽〶お〼〾ぁ〴お〰あお〷〴お〻〰えおぃ〷〸〽〺〸〽〶お〷〴おあ〰うお〰おあ〿〸〳〴ぁお〾ぅ〴ぁお〷〸あお〷〴〰〳お〼〰〺〸〽〶おぁ〴〰〳えおぃ〾おう〴〰ぅ〴お〷〴ぁおう〴〱お〷〴おう〰ぃ〲〷〴〳お〷〴ぁお〰あおあ〷〴おぃ〾〸〻〴〳おあ〻〾う〻えお〰〽〳おう〸ぃ〷お〶ぁ〴〰ぃお〲〰ぁ〴おあ〸ぇおぃ〸〼〴あおあ〷〴おぃぁ〸〴〳おぃ〾おぃ〷ぁ〾うお〷〴ぁお〵ぁ〰〸〻おぃ〷ぁ〴〰〳お〵ぁ〾〼お〾〽〴お〱〴〰〼おぃ〾お〰〽〾ぃ〷〴ぁお〰〽〳おあ〸ぇおぃ〸〼〴あお〸ぃお〵〴〻〻おあ〷〾ぁぃお〿〾〾ぁおぃ〷〸〽〶おあ〰〸〳お〱ぁい〲〴おえ〾いおぃ〾〾お〺〽〾うおう〷〰ぃお〸ぃお〸あおぃ〾お〵〰〸〻お〱いぃおぃ〷〴おあ〿〸〳〴ぁお〳〸〳お〽〾ぃお〻〾あ〴お〷〾〿〴おう〸ぃ〷おぃ〷〴おあ〸ぇぃ〷お〵〰〸〻いぁ〴おう〸ぃ〷おあぃ〸〻〻お〼〾ぁ〴お〲〰ぁ〴おあ〷〴お〼〰〳〴おぁ〴〰〳えおぃ〾おぃぁえお〵〾ぁおぃ〷〴おあ〴ぅ〴〽ぃ〷おぃ〸〼〴お〱ぁい〲〴お〰〻〼〾あぃお〵〾ぁ〶〾ぃお〷〸あお〾う〽おぃぁ〾い〱〻〴あお〰あお〷〴おう〰ぃ〲〷〴〳お〷〴ぁおあう〸〽〶お〷〴ぁあ〴〻〵お〾いぃおい〿〾〽おぃ〷〴おあ〻〴〽〳〴ぁお〻〸〽〴おう〾い〻〳おあ〷〴お〵〰〸〻お〰〶〰〸〽お〽〾おぃ〷〴おぃ〷ぁ〴〰〳おう〰あお〲〰ぁぁ〸〴〳おあ〰〵〴〻えおぃ〾おぃ〷〴お〱〴〰〼お〰〽〳お〵〰あぃ〴〽〴〳おぃ〷〴ぁ〴お〸おぃ〾〾おう〸〻〻おぃぁえお〰おあ〴ぅ〴〽ぃ〷おぃ〸〼〴お〲ぁ〸〴〳お〱ぁい〲〴お〷〴お〰ぁ〾あ〴お〰〽〳お〲〰〻〻〴〳お〷〸あお〼〴〽おぃ〾〶〴ぃ〷〴ぁお〷〴おぃ〾〻〳おぃ〷〴〼お〾〵お〷〸あお〿〻〰〽あお〰〽〳おあ〴〽ぃおぃ〷〴〼お〾いぃおう〸ぃ〷お〼〴ああ〰〶〴あお〾〵お〲〷〴〴ぁおぃ〾お〷〸あお〳〸あ〷〴〰ぁぃ〴〽〴〳お〿〴〾〿〻〴おあ〾〾〽おぃ〷〴ぁ〴おう〰あお〰〽お〰ぁ〼えお〾〵お〱ぁ〰ぅ〴おあ〲〾ぃ〲〷〼〴〽お〰ぁ〾い〽〳お〷〸〼お〰〽〾ぃ〷〴ぁお〱〰ぃぃ〻〴おう〰あお〵〾い〶〷ぃお〰〽〳おぃ〷〴お〺〸〽〶お〾〵お〴〽〶〻〰〽〳おう〰あお〶〻〰〳おぃ〾お〶〾お〱〰〲〺お〸〽ぃ〾お〷〸あお〾う〽お〲〾い〽ぃぁえお〸お〷〰ぅ〴お〷〴〰ぁ〳お〸ぃおあ〰〸〳おぃ〷〰ぃお〰〵ぃ〴ぁおぃ〷〰ぃお〳〰えお〽〾お〾〽〴お〱えおぃ〷〴お〽〰〼〴お〾〵お〱ぁい〲〴おう〾い〻〳お〴ぅ〴ぁお〷いぁぃお〰おあ〿〸〳〴ぁおぃ〷〴お〻〴ああ〾〽おう〷〸〲〷おぃ〷〴お〻〸ぃぃ〻〴お〲ぁ〴〰ぃいぁ〴お〷〰〳おぃ〰い〶〷ぃおぃ〷〴お〺〸〽〶おう〰あお〽〴ぅ〴ぁお〵〾ぁ〶〾ぃぃ〴〽お〷〴おぃ〾〻〳おいあおぃ〷〴お〵〻〰〶おう〰あお〲〰ぁ〴〵い〻お〵ぁ〴぀い〴〽〲えお〰〽〰〻えあ〸あお〱ぁ〴〰〺あおあい〱あぃ〸ぃいぃ〸〾〽お〲〸〿〷〴ぁお〷〴お〰〻あ〾おあい〶〶〴あぃあおぃ〷〴おいあ〴ぁおぃ〾お〹〾〸〽おぃ〷〴おう〾ぁ〳あおう〸ぃ〷おい〽〳〴ぁあ〲〾ぁ〴お〰〽〳お〿いぃおぃ〷〴おぁ〴あい〻ぃお〸〽おぃ〷〴お〵〻〰〶おうぁ〰〿〿〴ぁお〱〴〵〾ぁ〴おあい〱〼〸ああ〸〾〽"

syms = []
for i in list(txt):
    if i not in syms:
        syms += [i]
        
print(len(syms), syms)
```
```
26 ['ぃ', '〷', '〴', 'ぁ', 'お', 'う', '〰', 'あ', '〾', '〽', '〲', '〺', '〸', '〶', '〵', '〻', '〳', '〼', '〱', 'い', 'ぅ', 'え', 'ぇ', '〿', '\u3040', '〹']
```

A bunch of gibberish... Yet the source code reveals that the plain text is plain English and consists only of the alphabet 'A-Z ' (including the space), so 27 characters. We find 26 unique characters in our gibberish, so that seems all fine. This is a substitution-only cipher so some frequency analysis should do the trick!

## Exploitation

Our first step is to replace all these wonky characters with plain alphanumerical characters, then we'll make a quick overview of the frequency of each of the characters to start our frequency analysis!

```py
import matplotlib.pyplot as plt

newtxt = txt.translate(txt.maketrans(''.join(syms), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'))

lsts = unique(list(newtxt),return_counts=True)

plt.figure(figsize=(12,8))
plt.bar(lsts[0],lsts[1])
plt.show()
```
![](/assets/ctf/InvisCip_FreqAnalysis.png)

Clearly, the most frequent character is 'E'. From the given plain text alphabet space of 'A-Z ' (including a space) we can safely assume that the most frequent character is the space character. _To be sure of this you can check that 'E' never occurs twice in a row, whereas the other frequent characters do, as expected :)._ So let's replace 'E' with ' ' and see what the result looks like.

```py
newtxt.replace('E',' ')
```
```
ABCDC FGH IJKC G LMJN IO HKIAPGJQ FBIHC JGRC FGH DISCDA SDTKC BC BGQ JCCQ AI SC SIAB SDGUC GJQ FMHC OID ABC AMRCH MJ FBMKB BC PMUCQ FCDC FMPQ GJQ DTQC ABC LMJN IO CJNPGJQ FGH GA FGD FMAB BMR GJQ BGQ PCQ G NDCGA GDRV MJAI HKIAPGJQ AI QDMUC BMR ITA IO ABC PGJQ SGAAPC GOACD SGAAPC BGQ SCCJ OITNBA HMW AMRCH BGQ SDTKC PCQ BMH SDGUC PMAAPC GDRV GNGMJHA BMH OICH GJQ HMW AMRCH BGQ BMH RCJ SCCJ SCGACJ GJQ QDMUCJ MJAI OPMNBA GA PGHA BMH GDRV FGH HKGAACDCQ GJQ BC FGH OIDKCQ AI BMQC BMRHCPO MJ ABC FIIQH GJQ MJ PIJCPV XPGKCH GRIJN ABC RITJAGMJH IJC DGMJV QGV SDTKC PGV IJ ABC NDITJQ TJQCD G DTQC HBCQ PMHACJMJN AI ABC XGAACD IO ABC QDIXH IJ ABC DIIO GSIUC BMR BC FGH AMDCQ GJQ HMKL GA BCGDA GJQ DCGQV AI NMUC TX GPP BIXC MA HCCRCQ AI BMR ABGA ABCDC FGH JI THC OID BMR AI ADV AI QI GJVABMJN RIDC GH BC PGV ABMJLMJN BC HGF G HXMQCD IUCD BMH BCGQ RGLMJN DCGQV AI FCGUC BCD FCS BC FGAKBCQ BCD GH HBC AIMPCQ HPIFPV GJQ FMAB NDCGA KGDC HMW AMRCH HBC ADMCQ AI ABDIF BCD ODGMP ABDCGQ ODIR IJC SCGR AI GJIABCD GJQ HMW AMRCH MA OCPP HBIDA XIID ABMJN HGMQ SDTKC VIT AII LJIF FBGA MA MH AI OGMP STA ABC HXMQCD QMQ JIA PIHC BIXC FMAB ABC HMWAB OGMPTDC FMAB HAMPP RIDC KGDC HBC RGQC DCGQV AI ADV OID ABC HCUCJAB AMRC SDTKC GPRIHA OIDNIA BMH IFJ ADITSPCH GH BC FGAKBCQ BCD HFMJN BCDHCPO ITA TXIJ ABC HPCJQCD PMJC FITPQ HBC OGMP GNGMJ JI ABC ABDCGQ FGH KGDDMCQ HGOCPV AI ABC SCGR GJQ OGHACJCQ ABCDC M AII FMPP ADV G HCUCJAB AMRC KDMCQ SDTKC BC GDIHC GJQ KGPPCQ BMH RCJ AINCABCD BC AIPQ ABCR IO BMH XPGJH GJQ HCJA ABCR ITA FMAB RCHHGNCH IO KBCCD AI BMH QMHBCGDACJCQ XCIXPC HIIJ ABCDC FGH GJ GDRV IO SDGUC HKIAKBRCJ GDITJQ BMR GJIABCD SGAAPC FGH OITNBA GJQ ABC LMJN IO CJNPGJQ FGH NPGQ AI NI SGKL MJAI BMH IFJ KITJADV M BGUC BCGDQ MA HGMQ ABGA GOACD ABGA QGV JI IJC SV ABC JGRC IO SDTKC FITPQ CUCD BTDA G HXMQCD ABC PCHHIJ FBMKB ABC PMAAPC KDCGATDC BGQ AGTNBA ABC LMJN FGH JCUCD OIDNIAACJ BC AIPQ TH ABC OPGN FGH KGDCOTP ODCYTCJKV GJGPVHMH SDCGLH HTSHAMATAMIJ KMXBCD BC GPHI HTNNCHAH ABC THCD AI ZIMJ ABC FIDQH FMAB TJQCDHKIDC GJQ XTA ABC DCHTPA MJ ABC OPGN FDGXXCD SCOIDC HTSRMHHMIJ
```

If you ask me, that spacing looks quite natural for written English. Now, we could delve further into frequency analysis, but I'm lazy so let's call in some help. [Quipqiup](https://quipqiup.com/) to the rescue!

```
THERE WAS ONCE A KING OF SCOTLAND WHOSE NAME WAS ROBERT BRUCE HE HAD NEED TO BE BOTH BRAVE AND WISE FOR THE TIMES IN WHICH HE LIVED WERE WILD AND RUDE THE KING OF ENGLAND WAS AT WAR WITH HIM AND HAD LED A GREAT ARMY INTO SCOTLAND TO DRIVE HIM OUT OF THE LAND BATTLE AFTER BATTLE HAD BEEN FOUGHT SIX TIMES HAD BRUCE LED HIS BRAVE LITTLE ARMY AGAINST HIS FOES AND SIX TIMES HAD HIS MEN BEEN BEATEN AND DRIVEN INTO FLIGHT AT LAST HIS ARMY WAS SCATTERED AND HE WAS FORCED TO HIDE HIMSELF IN THE WOODS AND IN LONELY PLACES AMONG THE MOUNTAINS ONE RAINY DAY BRUCE LAY ON THE GROUND UNDER A RUDE SHED LISTENING TO THE PATTER OF THE DROPS ON THE ROOF ABOVE HIM HE WAS TIRED AND SICK AT HEART AND READY TO GIVE UP ALL HOPE IT SEEMED TO HIM THAT THERE WAS NO USE FOR HIM TO TRY TO DO ANYTHING MORE AS HE LAY THINKING HE SAW A SPIDER OVER HIS HEAD MAKING READY TO WEAVE HER WEB HE WATCHED HER AS SHE TOILED SLOWLY AND WITH GREAT CARE SIX TIMES SHE TRIED TO THROW HER FRAIL THREAD FROM ONE BEAM TO ANOTHER AND SIX TIMES IT FELL SHORT POOR THING SAID BRUCE YOU TOO KNOW WHAT IT IS TO FAIL BUT THE SPIDER DID NOT LOSE HOPE WITH THE SIXTH FAILURE WITH STILL MORE CARE SHE MADE READY TO TRY FOR THE SEVENTH TIME BRUCE ALMOST FORGOT HIS OWN TROUBLES AS HE WATCHED HER SWING HERSELF OUT UPON THE SLENDER LINE WOULD SHE FAIL AGAIN NO THE THREAD WAS CARRIED SAFELY TO THE BEAM AND FASTENED THERE I TOO WILL TRY A SEVENTH TIME CRIED BRUCE HE AROSE AND CALLED HIS MEN TOGETHER HE TOLD THEM OF HIS PLANS AND SENT THEM OUT WITH MESSAGES OF CHEER TO HIS DISHEARTENED PEOPLE SOON THERE WAS AN ARMY OF BRAVE SCOTCHMEN AROUND HIM ANOTHER BATTLE WAS FOUGHT AND THE KING OF ENGLAND WAS GLAD TO GO BACK INTO HIS OWN COUNTRY I HAVE HEARD IT SAID THAT AFTER THAT DAY NO ONE BY THE NAME OF BRUCE WOULD EVER HURT A SPIDER THE LESSON WHICH THE LITTLE CREATURE HAD TAUGHT THE KING WAS NEVER FORGOTTEN HE TOLD US THE FLAG WAS CAREFUL FREQUENCY ANALYSIS BREAKS SUBSTITUTION CIPHER HE ALSO SUGGESTS THE USER TO JOIN THE WORDS WITH UNDERSCORE AND PUT THE RESULT IN THE FLAG WRAPPER BEFORE SUBMISSION
```

Well well well... seems like we meet again, Robert Bruce...

Anyway, we got the flag!

```py
'wormcon{'+"CAREFUL FREQUENCY ANALYSIS BREAKS SUBSTITUTION CIPHER".replace(' ','_')+'}'
```

Ta-da!
```
wormcon{CAREFUL_FREQUENCY_ANALYSIS_BREAKS_SUBSTITUTION_CIPHER}
```
