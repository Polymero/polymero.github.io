---
title: ImaginaryCTF 2021 - Password Checker
category: CTF
tags: Write-up Web JavaScript Deobfuscation Brute-force
excerpt_separator: <!--more-->
---

Web -- 450 pts (15 solves) -- Chall author: Zyphen

An online 'password checker' with some (regex) obfuscated verification function. Running it through any online deobfuscator reveals the internal structure of the code. Some additional cleaning allows us to recover the restrictions on the input for us to get the flag. I chose to opt for brute-force (I like it rough) and to abuse the most ingenious invention of humankind, language.

<!--more-->

Check out write-ups by my teammates on [K3RN3L4RMY.com](http://k3rn3l4rmy.com/writeups)

## Exploration

![](/assets/ctf/PasswordChecker_challenge.png)

Upon first contact with the website we are greeted with a blindingly white page with a single input bar and button. We can put a 'password' in... aaaand... nothing happens, hah! Let's check under the hood of the website, the Inspector is on its way. Ah, it seems the console has logged some weird numbers for every time we hit the button, it seems like it executes a script with the input box entry as input. Shall we commence the ceremonial reading of the code?

```js
<html>
    <script>
eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--){d[e(c)]=k[c]||e(c)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('c 16=[\'2B\',\'2D\',\'3|2|0|1|4\',\'2I\',\'3g\',\'3w\',\'3y\',\'3p\',\'3q\',\'3r\',\'3s\',\'3c\',\'3b\',\'2W!!!\',\'2P\',\'2Z\',\'37\',\'1S.0\',\'39\',\'3a\',\'14\',\'36\',\'35\',\'31\',\'32\',\'33\',\'34\',\'38\',\'30\',\'2S\',\'2R\',\'2Q\',\'2T\',\'2U\',\'2Y\',\'2X\',\'2V\',\'3t\',\'3u\',\'3x\',\'3v\',\'3o\',\'3n\',\'3f\'];c 8=x;(f(s,1z){c g=x;r(!![]){R{c 1y=-6(g(3e))*6(g(3d))+-6(g(2O))*6(g(3h))+6(g(3i))*-6(g(3m))+-6(g(3l))+6(g(3k))+-6(g(U))+6(g(3j))*6(g(3z));L(1y===1z)w;S s[\'Y\'](s[\'14\']())}H(2A){s[\'Y\'](s[\'14\']())}}}(16,2o));c 5=[\'2r\',8(2n),8(2u),\'2t\',\'2l\',8(1h),\'2j\',8(1n),8(2k),8(2G),\'2M\',8(2L),\'Y\',8(19),8(1R),8(2E),8(1H),8(2y),8(2x),8(2b),8(b),8(26),8(17),8(1i),8(1d),8(2C),8(N),8(2z),\'2F\',8(2K),\'2J\',8(2H),\'2w\',8(18),8(29),8(2N),\'2s\',8(2m),8(2v),8(1A),8(1k),8(2p),\'2q\',8(1l),\'|\',\'0\',\'1\',\'2\',\'3\',\'4\'],13=[5[l],5[n],5[15],5[1N],5[1I],5[Z],5[11],5[1K],5[1M],5[1U],5[1V],5[25],5[K],5[1Z],5[20],5[1Y],5[1X],5[23],5[22],5[1L],5[1J],5[1O],5[1T],5[1P],5[1Q],5[27],5[2g],5[2h],5[4v],5[4u],5[4t],5[4w],5[4x],5[4A],5[4z],5[4y],5[4s],5[4r]];f A(1f,1e){k A=f(J,4l){J=J-12;c 1g=13[J];k 1g},A(1f,1e)}f x(1m,1a){k x=f(G,4k){G=G-1i;c 1c=16[G];k 1c},x(1m,1a)}c 9=A;(f(C,1j){c i=A;r(!![]){R{c 1b=6(i(4j))+-6(i(4m))*6(i(12))+6(i(1w))+6(i(4n))+-6(i(4q))*6(i(2i))+-6(i(4p))*6(i(4o))+6(i(4C));L(1b===1j)w;S C[5[K]](C[5[n]]())}H(4B){C[5[K]](C[5[n]]())}}}(13,4G));c X=[9(o),9(V),9(4Q),5[4P],9(1E),9(2c),5[4S],9(4R),9(10),9(4T),9(u),9(4V),9(4U),5[4O],9(4M),9(4N),9(4F),9(4E),9(1r),9(4D),9(4H),5[4I],9(1s),9(4L),9(1x),5[4K],5[4J],9(24),9(4i),9(4h),9(1o),9(1p)],d=t;(f(E,1q){c D=9,e=t;r(!![]){R{c 1D=-6(e(o))*6(e(u))+6(e(1t))*-6(e(3P))+-6(e(3O))+-6(e(3N))*-6(e(12))+6(e(3M))*-6(e(3A))+6(e(3Q))*6(e(3R))+6(e(1E));L(1D===1q)w;S E[D(10)](E[D(u)]())}H(3U){E[D(10)](E[D(u)]())}}}(X,3T));f t(1u,1v){k t=f(P,3S){P=P-1t;c 1G=X[P];k 1G},t(1u,1v)}c W=[d(1s),d(1r),9(3L),d(1o),d(3K),d(1W),d(3E),d(3D),d(v),9(3C),d(1p),d(3B),d(3F),d(3G),d(1w),d(3J),d(1x)];f F(1C,1B){k F=f(T,3I){T=T-U;c 1F=W[T];k 1F},F(1C,1B)}(f(z,2f){c 2e=9,Q=d,h=F;r(!![]){R{c 21=-6(h(1A))*-6(h(1n))+-6(h(1H))*6(h(19))+6(h(18))*6(h(17))+6(h(1k))+6(h(1l))+-6(h(1h))*6(h(1d))+-6(h(U));L(21===2f)w;S z[Q(V)](z[Q(2i)]())}H(3H){z[Q(V)](z[2e(u)]())}}}(W,3V));f 3W(7){c m=9,j=d,a=F,2d=j(4b)[a(2b)](5[4a]),2a=l;r(!![]){49(2d[2a++]){y 5[48]:c p=l;B;y 5[28]:4c(c q=l;q<7[m(2c)];q++){I+=7[a(b)](q),O^=7[a(b)](q),p=(p<<Z)-p+7[a(b)](q)};B;y 5[4d]:c O=l;B;y 5[4g]:c I=l;B;y 5[4f]:4e[a(1R)](I,O,p);!/[^1S.0]/[j(47)](7)&&I==46&&O==40&&p==-3Z&&7[j(v)](l)-7[a(b)](n)==n&&M[a(N)](7[a(b)](n)*7[m(o)](15)*7[a(b)](1N)/3Y)==3X&&7[a(b)](1I)+7[m(o)](Z)-7[j(v)](11)+7[a(b)](1K)==41&&M[a(N)](7[m(o)](1M)*7[a(b)](1U)/7[a(b)](1V)*7[a(b)](25))==42&&M[j(1W)](7[a(b)](1Z)/7[m(o)](K)/7[a(b)](20)*7[j(v)](1Y))==n&&(7[a(b)](1X)&&7[m(o)](22)==a(26)[j(24)]<<15)&&7[a(b)](11)==7[a(b)](23)&&M[a(N)](7[a(b)](1L)*7[a(b)](1J)/7[a(b)](1O))==28&&7[a(b)](1T)+7[j(v)](1P)-7[a(b)](1Q)==45&&7[a(b)](27)+7[a(b)](2g)+7[a(b)](2h)==44&&43(a(29));B};w}}',62,306,'|||||_0x4594|parseInt|_0x5d2aae|_0x5f1c40|_0x5980c6|_0x20d591|0xc3|var|_0x58abf4|_0x1ea2d6|function|_0x170af2|_0x5e7aef|_0x4fc4fe|_0x9be0fd|return|0x0|_0x842c|0x1|0x1b1|_0x1ea381|_0x44a8b7|while|_0x15743c|_0x54a0|0x1b8|0x1ab|break|_0x1790|case|_0x17a181|_0x55c1|continue|_0x5a3ddb|_0x26bcd0|_0x23cd40|_0x1833|_0x5cacdb|catch|_0x1a5e6c|_0x377eea|0xc|if|Math|0xc0|_0x2f116c|_0x20c82f|_0x34db26|try|else|_0x45c3e9|0xbf|0x1b3|_0x27fb|_0x4ad5|push|0x5|0x1c3|0x6|0x1ac|_0x4dca|shift|0x2|_0x5cac|0xcf|0xc8|0xc2|_0x23fb39|_0x29eb69|_0x570f07|0xc7|_0x2a598f|_0x14a33e|_0x3c91a9|0xc4|0xad|_0x236da7|0xc5|0xce|_0x520fde|0xca|0x1af|0x1b7|_0x4352ac|0x1b2|0x1b4|0x199|_0x13d82e|_0x5412b9|0x1ae|0x1ad|_0x34663d|_0x4a9d37|0xcc|_0x573bfc|_0x2a7d85|_0x51b01f|0x1b6|_0x5ce25c|_0x239ef8|0xc9|0x4|0x14|0x7|0x13|0x8|0x3|0x15|0x17|0x18|0xcb|ZYPH3NAFUR1GT_BMKLE|0x16|0x9|0xa|0x19c|0x10|0xf|0xd|0xe|_0x3589ec|0x12|0x11|0x1b0|0xb|0xc6|0x19|0x2e|0xcd|_0x41414f|0xc1|0x1b9|_0x32db26|_0x246cbe|_0x232ebb|0x1a|0x1b|0x1b5|20VbTLqJ|0xd4|42DPIOhl|0xb3|0xb4|0x3e0db|0xb5|240929VwwlKp|split|13681DjwrHy|153MASPMI|0xd6|0xd2|charCodeAt|0xbc|0xb2|0xb6|_0x236004|1298NDJRuz|0xaf|1SokIrZ|0xd1|178658HlLtWE|0xbe|0xb0|38287luFSSX|656587FXzDeH|0xd8|0xb1|498640Wruoqe|0xb8|0xbd|2HTpUWa|441046KVrdPb|log|700oyDWTZ|floor|6867bAuRrU|983121vgeeVc|Congrats|48937bEJivW|35906arOExL|139131prVwvx|572914UjDprZ|383EzPWPw|5387XbxlER|363969HwSspE|459706OQwMUO|1rfcdzr|166LKtHQY|1ljELRv|310Hdglyj|1134871bVGxkD|2341YnJcxT|285074XtEPmN|217211OwWaGK|0xd0|0xb9|498549IhYbqD|1BzNCnP|0xbb|0xae|0xd3|0xd5|0xba|0xd7|18igQKSS|test|4787emtElt|617341vNAjbx|336893pLjMBx|length|330Jeyjbe|2ZhzQhZ|41RPXVyE|6QMMLQT|4783CTkolx|25819YnJJGc|0xb7|0x1a7|0x1a2|0x1ba|0x19d|0x1aa|0x19a|0x1a0|_0x2a8de1|_0x4faf00|0x1a6|0x1a4|0x1c8|0x19e|0x1a9|0x1a3|0x19b|0x1a1|0x1a8|_0x5804b7|0x53e6d|_0x27106b|0x96016|boop|0x115|0x736|0x28dd475e|0x7e|0x72|0xcb1|alert|0x8a|0x74|0x7e8|0x19f|0x2d|switch|0x2c|0x1a5|for|0x2f|console|0x31|0x30|0x1be|0x1cc|0x1cb|_0x179003|_0x49d3e8|0x1c9|0x1bf|0x1bb|0x1ca|0x1bd|0x25|0x24|0x1e|0x1d|0x1c|0x1f|0x20|0x23|0x22|0x21|_0x196043|0x1c5|0x1c4|0x1d1|0x1c6|0x4ce49|0x1c7|0x29|0x2b|0x2a|0x1c2|0x1cd|0x1cf|0x28|0x26|0x1c0|0x1ce|0x27|0x1bc|0x1d0|0x1c1'.split('|'),0,{}))
    </script>
    <body>
        <form onsubmit="return false" class="form">
            Password: <input class="form-control" type="text" maxlength="30" id="Password" />
            <br />
            <input type="submit" value="Check" class="btn btn-primary" onclick="boop(document.getElementById('Password').value)" />
        </form>
    </body>
</html>
```

Nope, nope. I'm out. I am NOT reading that, eewww... It seems like some regex obfuscated JavaScript, let's just quickly push it through one of the many automatic deobfuscators found online. Having done that, we arrive at something that at least has some resemblence of structure.

```js
var _0x5cac = ['1298NDJRuz', '1SokIrZ', '3|2|0|1|4', '38287luFSSX', '1BzNCnP', '6QMMLQT', '25819YnJJGc', '4787emtElt', '617341vNAjbx', '336893pLjMBx', 'length', '217211OwWaGK', '285074XtEPmN', 'Congrats!!!', '2HTpUWa', '139131prVwvx', '1ljELRv', 'ZYPH3NAFUR1GT_BMKLE.0', '1134871bVGxkD', '2341YnJcxT', 'shift', '166LKtHQY', '1rfcdzr', '383EzPWPw', '5387XbxlER', '363969HwSspE', '459706OQwMUO', '310Hdglyj', '572914UjDprZ', '700oyDWTZ', 'log', '441046KVrdPb', 'floor', '6867bAuRrU', '35906arOExL', '48937bEJivW', '983121vgeeVc', '330Jeyjbe', '2ZhzQhZ', '4783CTkolx', '41RPXVyE', 'test', '18igQKSS', '498549IhYbqD'];
var _0x5f1c40 = _0x1790;
(function(_0x15743c, _0x4a9d37) {
    var _0x170af2 = _0x1790;
    while(!![]) {
        try {
            var _0x34663d = -parseInt(_0x170af2(0xb9)) * parseInt(_0x170af2(0xd0)) + -parseInt(_0x170af2(0xbd)) * parseInt(_0x170af2(0xbb)) + parseInt(_0x170af2(0xae)) * -parseInt(_0x170af2(0xd7)) + -parseInt(_0x170af2(0xba)) + parseInt(_0x170af2(0xd5)) + -parseInt(_0x170af2(0xbf)) + parseInt(_0x170af2(0xd3)) * parseInt(_0x170af2(0xb7));
            if(_0x34663d === _0x4a9d37) break;
            else _0x15743c['push'](_0x15743c['shift']())
        } catch(_0x236004) {
            _0x15743c['push'](_0x15743c['shift']())
        }
    }
}(_0x5cac, 0x3e0db));
var _0x4594 = ['split', _0x5f1c40(0xb4), _0x5f1c40(0xd6), '153MASPMI', '42DPIOhl', _0x5f1c40(0xc4), '20VbTLqJ', _0x5f1c40(0xca), _0x5f1c40(0xd4), _0x5f1c40(0xbe), '498640Wruoqe', _0x5f1c40(0xb1), 'push', _0x5f1c40(0xc2), _0x5f1c40(0xcb), _0x5f1c40(0xd1), _0x5f1c40(0xc9), _0x5f1c40(0xb2), _0x5f1c40(0xbc), _0x5f1c40(0xc1), _0x5f1c40(0xc3), _0x5f1c40(0xc6), _0x5f1c40(0xcf), _0x5f1c40(0xad), _0x5f1c40(0xc7), _0x5f1c40(0xaf), _0x5f1c40(0xc0), _0x5f1c40(0xb6), '178658HlLtWE', _0x5f1c40(0xd8), '656587FXzDeH', _0x5f1c40(0xb0), 'charCodeAt', _0x5f1c40(0xc8), _0x5f1c40(0xcd), _0x5f1c40(0xb8), '13681DjwrHy', _0x5f1c40(0xb3), _0x5f1c40(0xd2), _0x5f1c40(0xcc), _0x5f1c40(0xc5), _0x5f1c40(0xb5), '240929VwwlKp', _0x5f1c40(0xce), '|', '0', '1', '2', '3', '4'],
    _0x4dca = [_0x4594[0x0], _0x4594[0x1], _0x4594[0x2], _0x4594[0x3], _0x4594[0x4], _0x4594[0x5], _0x4594[0x6], _0x4594[0x7], _0x4594[0x8], _0x4594[0x9], _0x4594[0xa], _0x4594[0xb], _0x4594[0xc], _0x4594[0xd], _0x4594[0xe], _0x4594[0xf], _0x4594[0x10], _0x4594[0x11], _0x4594[0x12], _0x4594[0x13], _0x4594[0x14], _0x4594[0x15], _0x4594[0x16], _0x4594[0x17], _0x4594[0x18], _0x4594[0x19], _0x4594[0x1a], _0x4594[0x1b], _0x4594[0x1c], _0x4594[0x1d], _0x4594[0x1e], _0x4594[0x1f], _0x4594[0x20], _0x4594[0x21], _0x4594[0x22], _0x4594[0x23], _0x4594[0x24], _0x4594[0x25]];

function _0x55c1(_0x14a33e, _0x2a598f) {
    return _0x55c1 = function(_0x377eea, _0x49d3e8) {
        _0x377eea = _0x377eea - 0x1ac;
        var _0x3c91a9 = _0x4dca[_0x377eea];
        return _0x3c91a9
    }, _0x55c1(_0x14a33e, _0x2a598f)
}

function _0x1790(_0x520fde, _0x23fb39) {
    return _0x1790 = function(_0x5cacdb, _0x179003) {
        _0x5cacdb = _0x5cacdb - 0xad;
        var _0x570f07 = _0x5cac[_0x5cacdb];
        return _0x570f07
    }, _0x1790(_0x520fde, _0x23fb39)
}
var _0x5980c6 = _0x55c1;
(function(_0x5a3ddb, _0x236da7) {
    var _0x4fc4fe = _0x55c1;
    while(!![]) {
        try {
            var _0x29eb69 = parseInt(_0x4fc4fe(0x1cb)) + -parseInt(_0x4fc4fe(0x1c9)) * parseInt(_0x4fc4fe(0x1ac)) + parseInt(_0x4fc4fe(0x1ae)) + parseInt(_0x4fc4fe(0x1bf)) + -parseInt(_0x4fc4fe(0x1bd)) * parseInt(_0x4fc4fe(0x1b5)) + -parseInt(_0x4fc4fe(0x1ca)) * parseInt(_0x4fc4fe(0x1bb)) + parseInt(_0x4fc4fe(0x1c5));
            if(_0x29eb69 === _0x236da7) break;
            else _0x5a3ddb[_0x4594[0xc]](_0x5a3ddb[_0x4594[0x1]]())
        } catch(_0x196043) {
            _0x5a3ddb[_0x4594[0xc]](_0x5a3ddb[_0x4594[0x1]]())
        }
    }
}(_0x4dca, 0x4ce49));
var _0x4ad5 = [_0x5980c6(0x1b1), _0x5980c6(0x1b3), _0x5980c6(0x1c0), _0x4594[0x26], _0x5980c6(0x1b6), _0x5980c6(0x1b9), _0x4594[0x27], _0x5980c6(0x1ce), _0x5980c6(0x1c3), _0x5980c6(0x1bc), _0x5980c6(0x1b8), _0x5980c6(0x1c1), _0x5980c6(0x1d0), _0x4594[0x28], _0x5980c6(0x1cd), _0x5980c6(0x1cf), _0x5980c6(0x1c6), _0x5980c6(0x1d1), _0x5980c6(0x1b2), _0x5980c6(0x1c4), _0x5980c6(0x1c7), _0x4594[0x29], _0x5980c6(0x1b4), _0x5980c6(0x1c2), _0x5980c6(0x1ad), _0x4594[0x2a], _0x4594[0x2b], _0x5980c6(0x1b0), _0x5980c6(0x1cc), _0x5980c6(0x1be), _0x5980c6(0x1af), _0x5980c6(0x1b7)],
    _0x58abf4 = _0x54a0;
(function(_0x23cd40, _0x4352ac) {
    var _0x26bcd0 = _0x5980c6,
        _0x1ea2d6 = _0x54a0;
    while(!![]) {
        try {
            var _0x51b01f = -parseInt(_0x1ea2d6(0x1b1)) * parseInt(_0x1ea2d6(0x1b8)) + parseInt(_0x1ea2d6(0x199)) * -parseInt(_0x1ea2d6(0x19b)) + -parseInt(_0x1ea2d6(0x1a3)) + -parseInt(_0x1ea2d6(0x1a9)) * -parseInt(_0x1ea2d6(0x1ac)) + parseInt(_0x1ea2d6(0x19e)) * -parseInt(_0x1ea2d6(0x1a7)) + parseInt(_0x1ea2d6(0x1a1)) * parseInt(_0x1ea2d6(0x1a8)) + parseInt(_0x1ea2d6(0x1b6));
            if(_0x51b01f === _0x4352ac) break;
            else _0x23cd40[_0x26bcd0(0x1c3)](_0x23cd40[_0x26bcd0(0x1b8)]())
        } catch(_0x27106b) {
            _0x23cd40[_0x26bcd0(0x1c3)](_0x23cd40[_0x26bcd0(0x1b8)]())
        }
    }
}(_0x4ad5, 0x53e6d));

function _0x54a0(_0x13d82e, _0x5412b9) {
    return _0x54a0 = function(_0x20c82f, _0x5804b7) {
        _0x20c82f = _0x20c82f - 0x199;
        var _0x239ef8 = _0x4ad5[_0x20c82f];
        return _0x239ef8
    }, _0x54a0(_0x13d82e, _0x5412b9)
}
var _0x27fb = [_0x58abf4(0x1b4), _0x58abf4(0x1b2), _0x5980c6(0x1c8), _0x58abf4(0x1af), _0x58abf4(0x1a4), _0x58abf4(0x19c), _0x58abf4(0x1aa), _0x58abf4(0x19d), _0x58abf4(0x1ab), _0x5980c6(0x1ba), _0x58abf4(0x1b7), _0x58abf4(0x1a2), _0x58abf4(0x19a), _0x58abf4(0x1a0), _0x58abf4(0x1ae), _0x58abf4(0x1a6), _0x58abf4(0x1ad)];

function _0x1833(_0x2a7d85, _0x573bfc) {
    return _0x1833 = function(_0x45c3e9, _0x4faf00) {
        _0x45c3e9 = _0x45c3e9 - 0xbf;
        var _0x5ce25c = _0x27fb[_0x45c3e9];
        return _0x5ce25c
    }, _0x1833(_0x2a7d85, _0x573bfc)
}(function(_0x17a181, _0x232ebb) {
    var _0x246cbe = _0x5980c6,
        _0x34db26 = _0x58abf4,
        _0x5e7aef = _0x1833;
    while(!![]) {
        try {
            var _0x3589ec = -parseInt(_0x5e7aef(0xcc)) * -parseInt(_0x5e7aef(0xca)) + -parseInt(_0x5e7aef(0xc9)) * parseInt(_0x5e7aef(0xc2)) + parseInt(_0x5e7aef(0xc8)) * parseInt(_0x5e7aef(0xcf)) + parseInt(_0x5e7aef(0xc5)) + parseInt(_0x5e7aef(0xce)) + -parseInt(_0x5e7aef(0xc4)) * parseInt(_0x5e7aef(0xc7)) + -parseInt(_0x5e7aef(0xbf));
            if(_0x3589ec === _0x232ebb) break;
            else _0x17a181[_0x34db26(0x1b3)](_0x17a181[_0x34db26(0x1b5)]())
        } catch(_0x2a8de1) {
            _0x17a181[_0x34db26(0x1b3)](_0x17a181[_0x246cbe(0x1b8)]())
        }
    }
}(_0x27fb, 0x96016));

function boop(_0x5d2aae) {
    var _0x842c = _0x5980c6,
        _0x9be0fd = _0x58abf4,
        _0x20d591 = _0x1833,
        _0x32db26 = _0x9be0fd(0x1a5)[_0x20d591(0xc1)](_0x4594[0x2c]),
        _0x41414f = 0x0;
    while(!![]) {
        switch(_0x32db26[_0x41414f++]) {
            case _0x4594[0x2d]:
                var _0x1ea381 = 0x0;
                continue;
            case _0x4594[0x2e]:
                for(var _0x44a8b7 = 0x0; _0x44a8b7 < _0x5d2aae[_0x842c(0x1b9)]; _0x44a8b7++) {
                    _0x1a5e6c += _0x5d2aae[_0x20d591(0xc3)](_0x44a8b7), _0x2f116c ^= _0x5d2aae[_0x20d591(0xc3)](_0x44a8b7), _0x1ea381 = (_0x1ea381 << 0x5) - _0x1ea381 + _0x5d2aae[_0x20d591(0xc3)](_0x44a8b7)
                };
                continue;
            case _0x4594[0x2f]:
                var _0x2f116c = 0x0;
                continue;
            case _0x4594[0x30]:
                var _0x1a5e6c = 0x0;
                continue;
            case _0x4594[0x31]:
                console[_0x20d591(0xcb)](_0x1a5e6c, _0x2f116c, _0x1ea381);
                !/[^ZYPH3NAFUR1GT_BMKLE.0]/ [_0x9be0fd(0x19f)](_0x5d2aae) && _0x1a5e6c == 0x7e8 && _0x2f116c == 0x7e && _0x1ea381 == -0x28dd475e && _0x5d2aae[_0x9be0fd(0x1ab)](0x0) - _0x5d2aae[_0x20d591(0xc3)](0x1) == 0x1 && Math[_0x20d591(0xc0)](_0x5d2aae[_0x20d591(0xc3)](0x1) * _0x5d2aae[_0x842c(0x1b1)](0x2) * _0x5d2aae[_0x20d591(0xc3)](0x3) / 0x736) == 0x115 && _0x5d2aae[_0x20d591(0xc3)](0x4) + _0x5d2aae[_0x842c(0x1b1)](0x5) - _0x5d2aae[_0x9be0fd(0x1ab)](0x6) + _0x5d2aae[_0x20d591(0xc3)](0x7) == 0x72 && Math[_0x20d591(0xc0)](_0x5d2aae[_0x842c(0x1b1)](0x8) * _0x5d2aae[_0x20d591(0xc3)](0x9) / _0x5d2aae[_0x20d591(0xc3)](0xa) * _0x5d2aae[_0x20d591(0xc3)](0xb)) == 0xcb1 && Math[_0x9be0fd(0x19c)](_0x5d2aae[_0x20d591(0xc3)](0xd) / _0x5d2aae[_0x842c(0x1b1)](0xc) / _0x5d2aae[_0x20d591(0xc3)](0xe) * _0x5d2aae[_0x9be0fd(0x1ab)](0xf)) == 0x1 && (_0x5d2aae[_0x20d591(0xc3)](0x10) && _0x5d2aae[_0x842c(0x1b1)](0x12) == _0x20d591(0xc6)[_0x9be0fd(0x1b0)] << 0x2) && _0x5d2aae[_0x20d591(0xc3)](0x6) == _0x5d2aae[_0x20d591(0xc3)](0x11) && Math[_0x20d591(0xc0)](_0x5d2aae[_0x20d591(0xc3)](0x13) * _0x5d2aae[_0x20d591(0xc3)](0x14) / _0x5d2aae[_0x20d591(0xc3)](0x15)) == 0x2e && _0x5d2aae[_0x20d591(0xc3)](0x16) + _0x5d2aae[_0x9be0fd(0x1ab)](0x17) - _0x5d2aae[_0x20d591(0xc3)](0x18) == 0x74 && _0x5d2aae[_0x20d591(0xc3)](0x19) + _0x5d2aae[_0x20d591(0xc3)](0x1a) + _0x5d2aae[_0x20d591(0xc3)](0x1b) == 0x8a && alert(_0x20d591(0xcd));
                continue
        };
        break
    }
}
```

Finally, we can improve readability a lot by using appropriate variable and function names. Also, side note, I am not a fan of JS, so I translated it to Python using some extra functions in order to emulate JS behaviour. _Who thought using 64-bit ints as a standard, but only use 32-bit ints for bit shift operations (<<, >>) was a good idea... O.o_

```py
# Imports
import random
from numpy import unique

#
# Functions to emulate JS behaviour
#

def parseInt( s ):
    """ Returns integer from string according to JS parseInt(). """
    k = 0
    while all( [i in '0123456789-' for i in list(s[:k])] ):
        k += 1
    if s[:k-1] != '':
        return int(s[:k-1])
    else:
        return None

def JSLR( x ):
    """ Returns 5-bit left shifted (32-bit op) 64-bit int according to JS. """
    x = 0xffffffff & ( x << 5 )
    if x > 0x7fffffff:
        return -(~(x - 1) & 0xffffffff)
    else:
        return x

#
# Order of code is similar to the obfuscated JS
#

List_1 = ['1298NDJRuz', '1SokIrZ', '3|2|0|1|4', '38287luFSSX', '1BzNCnP', '6QMMLQT', '25819YnJJGc', '4787emtElt', '617341vNAjbx', '336893pLjMBx', 'length', '217211OwWaGK', '285074XtEPmN', 'Congrats!!!', '2HTpUWa', '139131prVwvx', '1ljELRv', 'ZYPH3NAFUR1GT_BMKLE.0', '1134871bVGxkD', '2341YnJcxT', 'shift', '166LKtHQY', '1rfcdzr', '383EzPWPw', '5387XbxlER', '363969HwSspE', '459706OQwMUO', '310Hdglyj', '572914UjDprZ', '700oyDWTZ', 'log', '441046KVrdPb', 'floor', '6867bAuRrU', '35906arOExL', '48937bEJivW', '983121vgeeVc', '330Jeyjbe', '2ZhzQhZ', '4783CTkolx', '41RPXVyE', 'test', '18igQKSS', '498549IhYbqD']  

def Function_2( i ):
    return List_1[ i - 173 ]

def Operation_1():
    global List_1
    lim = 0x3e0db
    while True:
        try:
            calc =  -parseInt(Function_2(0xb9)) * parseInt(Function_2(0xd0)) + -parseInt(Function_2(0xbd)) * parseInt(Function_2(0xbb)) + parseInt(Function_2(0xae)) * -parseInt(Function_2(0xd7)) + -parseInt(Function_2(0xba)) + parseInt(Function_2(0xd5)) + -parseInt(Function_2(0xbf)) + parseInt(Function_2(0xd3)) * parseInt(Function_2(0xb7));
            if calc == lim:
                break
            else:
                List_1 = List_1[1:] + [List_1[0]]
        except:
            List_1 = List_1[1:] + [List_1[0]]

Operation_1()

List_2A = ['split', Function_2(0xb4), Function_2(0xd6), '153MASPMI', '42DPIOhl', Function_2(0xc4), '20VbTLqJ', Function_2(0xca), Function_2(0xd4), Function_2(0xbe), '498640Wruoqe', Function_2(0xb1), 'push', Function_2(0xc2), Function_2(0xcb), Function_2(0xd1), Function_2(0xc9), Function_2(0xb2), Function_2(0xbc), Function_2(0xc1), Function_2(0xc3), Function_2(0xc6), Function_2(0xcf), Function_2(173), Function_2(0xc7), Function_2(0xaf), Function_2(0xc0), Function_2(0xb6), '178658HlLtWE', Function_2(0xd8), '656587FXzDeH', Function_2(0xb0), 'charCodeAt', Function_2(0xc8), Function_2(0xcd), Function_2(0xb8), '13681DjwrHy', Function_2(0xb3), Function_2(0xd2), Function_2(0xcc), Function_2(0xc5), Function_2(0xb5), '240929VwwlKp', Function_2(0xce), '|', '0', '1', '2', '3', '4']

List_2B = [List_2A[0x0], List_2A[0x1], List_2A[0x2], List_2A[0x3], List_2A[0x4], List_2A[0x5], List_2A[0x6], List_2A[0x7], List_2A[0x8], List_2A[0x9], List_2A[0xa], List_2A[0xb], List_2A[0xc], List_2A[0xd], List_2A[0xe], List_2A[0xf], List_2A[0x10], List_2A[0x11], List_2A[0x12], List_2A[0x13], List_2A[0x14], List_2A[0x15], List_2A[0x16], List_2A[0x17], List_2A[0x18], List_2A[0x19], List_2A[0x1a], List_2A[0x1b], List_2A[0x1c], List_2A[0x1d], List_2A[0x1e], List_2A[0x1f], List_2A[0x20], List_2A[0x21], List_2A[0x22], List_2A[0x23], List_2A[0x24], List_2A[0x25]]

def Function_1( i ):
    return List_2B[ i - 428 ]

def Operation_2():
    global List_2A, List_2B
    lim = 0x4ce49
    while True:
        try:
            calc = parseInt(Function_1(0x1cb)) + -parseInt(Function_1(0x1c9)) * parseInt(Function_1(0x1ac)) + parseInt(Function_1(0x1ae)) + parseInt(Function_1(0x1bf)) + -parseInt(Function_1(0x1bd)) * parseInt(Function_1(0x1b5)) + -parseInt(Function_1(0x1ca)) * parseInt(Function_1(0x1bb)) + parseInt(Function_1(0x1c5))
            if calc == lim:
                break
            else:
                List_2B = List_2B[1:] + [List_2B[0]]
        except:
            List_2B = List_2B[1:] + [List_2B[0]]

Operation_2()

List_3 = [Function_1(0x1b1), Function_1(0x1b3), Function_1(0x1c0), List_2A[0x26], Function_1(0x1b6), Function_1(0x1b9), List_2A[0x27], Function_1(0x1ce), Function_1(0x1c3), Function_1(0x1bc), Function_1(0x1b8), Function_1(0x1c1), Function_1(0x1d0), List_2A[0x28], Function_1(0x1cd), Function_1(0x1cf), Function_1(0x1c6), Function_1(0x1d1), Function_1(0x1b2), Function_1(0x1c4), Function_1(0x1c7), List_2A[0x29], Function_1(0x1b4), Function_1(0x1c2), Function_1(0x1ad), List_2A[0x2a], List_2A[0x2b], Function_1(0x1b0), Function_1(0x1cc), Function_1(0x1be), Function_1(0x1af), Function_1(0x1b7)]

def Function_3( i ):
    return List_3[ i - 0x199 ]

def Operation_3():
    global List_3
    lim = 0x53e6d
    while True:
        try:
            calc = -parseInt(Function_3(0x1b1)) * parseInt(Function_3(0x1b8)) + parseInt(Function_3(0x199)) * -parseInt(Function_3(0x19b)) + -parseInt(Function_3(0x1a3)) + -parseInt(Function_3(0x1a9)) * -parseInt(Function_3(0x1ac)) + parseInt(Function_3(0x19e)) * -parseInt(Function_3(0x1a7)) + parseInt(Function_3(0x1a1)) * parseInt(Function_3(0x1a8)) + parseInt(Function_3(0x1b6))
            if calc == lim:
                break
            else:
                List_3 = List_3[1:] + [List_3[0]]
        except:
            List_3 = List_3[1:] + [List_3[0]]

Operation_3()

List_4 = [Function_3(0x1b4), Function_3(0x1b2), Function_1(0x1c8), Function_3(0x1af), Function_3(0x1a4), Function_3(0x19c), Function_3(0x1aa), Function_3(0x19d), Function_3(0x1ab), Function_1(0x1ba), Function_3(0x1b7), Function_3(0x1a2), Function_3(0x19a), Function_3(0x1a0), Function_3(0x1ae), Function_3(0x1a6), Function_3(0x1ad)]

def Function_4( i ):
    return List_4[ i - 0xbf ]

def Operation_4():
    global List_4
    lim = 0x96016
    while True:
        try:
            calc = -parseInt(Function_4(0xcc)) * -parseInt(Function_4(0xca)) + -parseInt(Function_4(0xc9)) * parseInt(Function_4(0xc2)) + parseInt(Function_4(0xc8)) * parseInt(Function_4(0xcf)) + parseInt(Function_4(0xc5)) + parseInt(Function_4(0xce)) + -parseInt(Function_4(0xc4)) * parseInt(Function_4(0xc7)) + -parseInt(Function_4(0xbf))
            if calc == lim:
                break
            else:
                List_4 = List_4[1:] + [List_4[0]]
        except:
            List_4 = List_4[1:] + [List_4[0]]

Operation_4()

def boop( INPUT ):
    var_1 = 0
    var_2 = 0
    var_3 = 0
    for j in range(len(INPUT)):
        var_1 += ord(INPUT[j])
        var_2 ^= ord(INPUT[j])
        var_3 = JSLR( var_3 ) - var_3 + ord(INPUT[j])
    return (var_1, var_2, var_3)
```

From the final bit of the deobfuscated JS, we also find the criteria our input is checked against. It seems our input will be the flag itself, as long as it satisfies the following restrictions:
1. All chars in { ZYPH3NAFUR1GT_BMKLE.0 } 
2. Sum of chars is 2024
3. Xor product of chars is 126
4. Annoying var_3 function returns -685590366
5. c0 - c1 = 1
6. floor( c1 * c2 * c3 / 0x736 ) = 0x115
7. c4 + c5 - c6 + c7 = 0x72
8. floor( c8 * c9 / c10 * c11 ) = 0xcb1
9. floor( c13 / c12 / c14 * c15 ) = 0x1
10. c18 = 84
11. c6 = c17
12. floor( c19 * c20 / c21 ) = 0x2e
13. c22 + c23 - c24 = 0x74
14. c25 + c26 + c27 = 0x8a

Alright, we can work with this!

## Exploitation

Since the possible number of characters is quite small, only 21, and the individual restrictions contain at most 4 characters, we can easily brute-force all possible combinations of each restriction. From that we might get an idea of the total search space we are dealing with. To do this, I used the script below.

```py
# Character alphabet
ALP = 'ZYPH3NAFUR1GT_BMKLE.0'
ORD = [ord(i) for i in list(ALP)]

def wild_guess():
    """ Returns a wild guess (of lenth 28) given the alphabet constraint. """
    return ''.join([random.SystemRandom().choice(list(ALP)) for _ in range(28)])

def get_possible():
    """ Returns list of possible char combinations per constraint (5 through 14). """
    
    # Combined constraints 5,6 on chars 0,1,2,3
    pos_c0c1 = []
    for c0 in list(ALP):
        for c1 in list(ALP):
            if ( ord(c0) - ord(c1) == 1 ):
                pos_c0c1 += [ c0 + c1 ]
    pos_c1c2c3 = []
    for c1 in list(ALP):
        for c2 in list(ALP):
            for c3 in list(ALP):
                if ( int( ord(c1) * ord(c2) * ord(c3) / 1846 ) == 277 ):
                    pos_c1c2c3 += [ c1 + c2 + c3 ]
    pos_c1 = [i[1] for i in pos_c0c1 if i[1] in [j[0] for j in pos_c1c2c3]]
    pos_c0 = [chr(ord(i)+1) for i in pos_c1]
    pos_c2c3 = [i[1:] for i in pos_c1c2c3 if i[0] in pos_c1]
    print('c0 :', len(pos_c0))
    print('c1 :', 1, len(pos_c1))
    print('c2 c3 :', len(pos_c2c3))

    # Constraint 7 on chars 4,5,6,7
    pos_c4c5c6c7 = []
    for c4 in list(ALP):
        for c5 in list(ALP):
            for c6 in list(ALP):
                for c7 in list(ALP):
                    if ( ord(c4) + ord(c5) - ord(c6) + ord(c7) == 114 ):
                        pos_c4c5c6c7 += [ c4 + c5 + c6 + c7 ]
    print('c4 c5 c6 c7 :', len(pos_c4c5c6c7))

    # Constraint 8 on chars 8,9,10,11
    pos_c8c9c10c11 = []
    for c8 in list(ALP):
        for c9 in list(ALP):
            for c10 in list(ALP):
                for c11 in list(ALP):
                    if ( int( ord(c8) * ord(c9) / ord(c10) * ord(c11) ) == 3249 ):
                        pos_c8c9c10c11 += [ c8 + c9 + c10 + c11 ]
    print('c8 c9 c10 c11 :', len(pos_c8c9c10c11))
    
    # Constraint 9 on chars 12,13,14,15
    pos_c12c13c14c15 = []
    for c12 in list(ALP):
        for c13 in list(ALP):
            for c14 in list(ALP):
                for c15 in list(ALP):
                    if ( int( ord(c13) / ord(c12) / ord(c14) * ord(c15) ) == 1 ):
                        pos_c12c13c14c15 += [ c12 + c13 + c14 + c15 ]
    print('c12 c13 c14 c15 :', len(pos_c12c13c14c15))
    
    # Char 16 has no constraints due to (Int & Int) behaviour of JS
    pos_c16 = list(ALP)
    print('c16 :', len(pos_c16))
    
    # Constraint 11 on char 17
    pos_c17 = list(unique([i[2] for i in pos_c4c5c6c7]))
    print('c17 :', 1, len(pos_c17))
    
    # Constraint 10 on char 18
    pos_c18 = [84]
    print('c18 :', 1)
    
    # Constraint 12 on chars 19,20,21
    pos_c19c20c21 = []
    for c19 in list(ALP):
        for c20 in list(ALP):
            for c21 in list(ALP):
                if ( int( ord(c19) * ord(c20) / ord(c21) ) == 46 ):
                    pos_c19c20c21 += [ c19 + c20 + c21 ]
    print('c19 c20 c21 :', len(pos_c19c20c21))
    
    # Constraint 13 on chars 22,23,24
    pos_c22c23c24 = []
    for c22 in list(ALP):
        for c23 in list(ALP):
            for c24 in list(ALP):
                if ( ord(c22) + ord(c23) - ord(c24) == 116 ):
                    pos_c22c23c24 += [ c22 + c23 + c24 ]
    print('c22 c23 c24 :', len(pos_c22c23c24))

    # Constraint 14 on chars 25,26,27
    pos_c25c26c27 = []
    for c25 in list(ALP):
        for c26 in list(ALP):
            for c27 in list(ALP):
                if ( ord(c25) + ord(c26) + ord(c27) == 138):
                    pos_c25c26c27 += [ c25 + c26 + c27 ]
    print('c25 c26 c27 :', len(pos_c25c26c27))

    # Return list of lists of lists #listlife
    return [pos_c0,pos_c1,pos_c2c3,pos_c4c5c6c7,pos_c8c9c10c11,pos_c12c13c14c15,pos_c16,pos_c17,pos_c18,pos_c19c20c21,pos_c22c23c24,pos_c25c26c27]
    
lsts = get_possible()
```

To find a rough estimate of our search space (number of guesses we would need to find the right input) we simply multiply the possibilities of each set of characters, as defined by the individual restrictions. Turns out we might be doomed as
```
6*1*17*1477*36*88274*21*1*1*148*33*1 = 49103327620315584 ~ 2**56
```
is not really feasible to overpower by brute-force. Any truly random password could not have been cracked this way. However! Although Zyphen himself might be immortal, his password management skills are equivalent to those of a mere mortal human. In other words, his password seemed to contain some kind of structure... Yes, I am talking about language. In fact, it is even worse as he used his own name in his password. A clear case of hubris if you'd ask me! 

Through creating some wild guesses for the password using the restrictions above, I noticed it was possible for the password to start with 'ZYPH3N\_'! Let's see how much our search space improves if we assume that the password begins with 'ZYPH3N\_P' (where the 'P' comes from constraint 7). Now our space contains
```
36*88274*21*1*1*148*33*1 = 325934443296 ~ 2**39
```
Eerhmm... yeah no, this ain't happening. Not any time soon anyway, the search space is still too large to brute-force. We know c17,c18 is '\_T' and that the password ends with '...'. Maybe we can find out what the third word is by only considering the relevant possiblities. By searching for patterns I suddenly read 'T0RTUR3', a sh0ck1ng r3v3l4t10n. Okay, okay, how about now?
```
36*88274*21 = 66735144 ~ 2**26
```
Aha! Now we've got something that we can smash into bits. So let's don our boxing gloves and get ready to use some force, ***B R U T A L L Y***.

```py
assumption = 'ZYPH3N_P'
for c8,c9,c10,c11 in lsts[4]:
    for c12,c13,c14,c15 in lsts[5]:
        for c16 in lsts[6]:
            c17 = '_'
            c18 = 'T'
            c19,c20,c21,c22,c23,c24,c25,c26,c27 = list('0RTUR3...')
            trial = ''.join([assumption,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18,c19,c20,c21,c22,c23,c24,c25,c26,c27])
            check = boop( trial )
            if (check[0] == 2024) and (check[1] == 126) and (abs(check[2] - -685590366) < 1000):
                print(trial, check)
```

With the above code I actually managed to find two valid inputs, and there might even be more! 
```
ZYPH3N_P1Z_F13FRT_T0RTUR3... (2024, 126, -685590366)
ZYPH3N_P1Z_F0RG3T_T0RTUR3... (2024, 126, -685590366)
```
I am sure Zyphen would be delighted to know that I recovered his other password as well :). Maybe he'll even give me an extra flag ;).

Ta-da!
```
ictf{ZYPH3N_P1Z_F0RG3T_T0RTUR3...}
```
