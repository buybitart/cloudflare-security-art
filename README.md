# Cloudflare Security Configuration (Free Plan) 

I’m Aksana (5Ksana), founder of the open‑source [BitcoinArt project](https://github.com/buybitart/bitcoinart) . My husband Aliaksandr, a few friends, and I built this platform with our own savings so that Bitcoin artists everywhere can run a fully self‑hosted site, sell their handmade work, and accept payments in BTC, USDT (BTCPay), or credit card (Stripe) without middlemen or censorship.

If you like what we’re doing, please consider a donation-any amount helps us keep improving the gallery, auction tools, and multilingual support for creators around the world. Thank you for helping us protect artistic freedom and grow Bitcoin culture.

If you'd like to support the project, please visit the [**donation page**](https://buybitart.com/support). or If this repo made your life a little easier, please consider dropping a star ⭐ it really helps and totally makes my day! Thank you! 💖

**This guide will help you protect your website using Cloudflare. It includes firewall rules, DDoS protection, security headers, and bot settings.**

**It includes**:

- ✅ Firewall rules  
- ✅ DDoS protection  
- ✅ Security headers  
- ✅ Bot management settings
---
**My Cloudflare rule is**:

- ✅ Tested and safe  
- ✅ Does **not** break your site  
- ✅ Blocks harmful bots, including AI scrapers  
- ✅ Based on a [**ZERO TRUST**](https://4sysops.com/archives/block-ai-scrapers-and-other-web-parasites-with-cloudflare/) approach

**AI bots try to copy your content!**.
See [**How AI is stealing your art**](https://juliabausenhardt.com/how-ai-is-stealing-your-art/) and [**‘Mass theft’: Thousands of artists call for AI art auction to be cancelled**](https://www.theguardian.com/technology/2025/feb/10/mass-theft-thousands-of-artists-call-for-ai-art-auction-to-be-cancelled) 
> **"One of the main points of art is to dialogue with culture.**  
> Even if unintentional, every piece of art reflects the unique background of its creator-shaped by food, religion, music, ethics, visual art, and more.  
> 
> Imagine a child raised in isolation, shown only paintings 16 hours a day, and punished if their weekly drawing doesn't replicate those images closely enough. They don’t know why they draw-they just mimic. They aren’t creating. They aren’t dialoguing with art.  
> 
> A computer is even simpler. It doesn't feel, doesn't reflect, doesn't remember the sound of jazz in the 1920s or the first time it saw Warhol.  
> 
> But a human artist does.  
> They carry experience, emotion, and intention. They borrow from the past, mix it with the present, and speak in their own voice. That’s art. That’s the difference.
>
> When art is just imitation for profit, it’s empty. But when it speaks-it matters."

AI pretend to be search engines, but they don't bring you visitors.  
Some even use fake user agents, so basic Cloudflare settings may not stop them.
This rule blocks **all** bots by default, and then **only allows useful bots** that help your website get indexed.

| Step | Description |
|------|-------------|
| [**STEP 1 – Web Application Firewall (WAF) Rules**](#step-1) | Blocks bots, crawlers, exploits and malicious requests (Parts 1‑5). |
| [**STEP 2 – DDoS L7 Protection & Rate Limiting**](#step-2) | Adds Layer‑7 override and rate limits to stop floods. |
| [**STEP 3 – Bot Management**](#step-3) | Configures Cloudflare bot settings to block AI and unwanted bots. |
| [**STEP 4 – Security Headers**](#step-4) | Sets recommended HTTP headers to harden the site. |

> [!IMPORTANT]  
> It is also recommended to **disable** the **`Bot Fight Mode`** feature in the **`Security`** tab.  
> This guide already blocks all unwanted bots and AI crawlers while allowing only the important and trusted bots used for indexing your site such as:  
> - google  
> - bing  
> - slurp  
> - duckduckbot  
> - cloudflare  
> Because of this, there is no need to enable Bot Fight Mode as it could interfere with these allowed bots and disrupt proper indexing.

---

<a id="step-1"></a>
## STEP 1 – Web Application Firewall (WAF) Rules

Copy these expressions into your Cloudflare dashboard for custom WAF rules.

- Go to Security > **WAF** > **Custom rules**. 
- To create a new empty rule, select Create rule. 

Read [Create a custom rule in the dashboard](https://developers.cloudflare.com/waf/custom-rules/create-dashboard/).

<img width="1066" height="410" alt="image" src="https://github.com/user-attachments/assets/6c77eaae-0e9a-496c-84b4-2a91518f7af3" />


### Part 1 – Block Bot Parasites

This rule stops bad automated web traffic by checking each request and blocking empty or strange User‑Agent names like headless browsers or scanners and traffic from certain IP groups that use "siteaudit" and Host headers that have ":80" or ":443" and wrong Cloudflare cookies and any Cloudflare client.bot that is not a verified search crawler or an ACME challenge and any HTTP/1.0 or HTTP/1.1 request unless it asks for "/robots.txt" or comes from a real search bot or an ACME check.

> NOTE🔒 **This rule stops about 90% of all threats. It cuts off bad bot traffic before it reaches the application.**

**Action:** Block

```plaintext
(
  (
  http.user_agent eq ""
  or http.user_agent eq " "
  or http.user_agent eq "'"
  or http.request.headers["user-agent"][0] eq ""
  or lower(http.user_agent) contains "puppeteer"
  or lower(http.user_agent) contains "phantomjs"
  or lower(http.user_agent) contains "selenium"
  or lower(http.user_agent) contains "slimerjs"
  or lower(http.user_agent) contains "nightmare"
  or lower(http.user_agent) contains "casperjs"
  or lower(http.user_agent) contains "pyppeteer"
  )
  or (ip.src.asnum in {135061 23724 4808} and http.user_agent contains "siteaudit")
  or (http.host contains ":80")
  or (http.host contains ":443")
  or (
    http.cookie contains "cf_use_ob="
    and not http.cookie contains "0"
    and not http.cookie contains "80"
    and not http.cookie contains "443"
    and not cf.client.bot
  )
  or (
    cf.client.bot
    and not (
      (
        cf.verified_bot_category in {"Search Engine Crawler"}
        and (
          lower(http.user_agent) contains "google"
          or lower(http.user_agent) contains "bing"
          or lower(http.user_agent) contains "slurp"
          or lower(http.user_agent) contains "duckduckbot"
          or lower(http.user_agent) contains "cloudflare"

        )
      )
      or lower(http.user_agent) contains "google-inspectiontool"
      or lower(http.user_agent) contains "google-siteverification"
      or lower(http.user_agent) contains "googlebot"
      or lower(http.user_agent) contains "chrome-lighthouse"
      or http.request.uri.path contains "acme-challenge"
      or lower(http.user_agent) contains "adsbot-google"
      or lower(http.user_agent) contains "google-adwords"
    
       )
  )
)
or
(
  http.request.version in {"HTTP/1.0" "HTTP/1.1"}
  and not (
    cf.client.bot
    or lower(http.user_agent) contains "google"
    or lower(http.user_agent) contains "bing"
    or lower(http.user_agent) contains "slurp"
    or lower(http.user_agent) contains "duckduckbot"
    or lower(http.user_agent) contains "cloudflare"
    or lower(http.user_agent) contains "google-inspectiontool"
    or lower(http.user_agent) contains "google-siteverification"
    or lower(http.user_agent) contains "googlebot"
    or lower(http.user_agent) contains "chrome-lighthouse"
    or http.request.uri.path contains "acme-challenge"
    or lower(http.user_agent) contains "adsbot-google"
    or lower(http.user_agent) contains "google-adwords"

  )
)
```

### Part 2 – Block AI and Bad Crawlers

This rule blocks many automated bots and crawlers. It stops AI crawlers like "amazonbot", "gptbot", "claudebot", "mistralai" and others. It also blocks any user agent with "bot", "crawl" or "spider" in its name from certain IP groups. It still allows real search engines like Google or Bing and ACME challenge requests.

**Action:** Block

```plaintext
(
  lower(http.user_agent) contains "amazonbot"           or
  lower(http.user_agent) contains "googleother"         or
  lower(http.user_agent) contains "gptbot"              or
  lower(http.user_agent) contains "oai-searchbot"       or
  lower(http.user_agent) contains "chatgpt"             or
  lower(http.user_agent) contains "perplexitybot"       or
  lower(http.user_agent) contains "claudebot"           or
  lower(http.user_agent) contains "sbintuitionsbot"     or
  lower(http.user_agent) contains "mistralai"           or
  lower(http.user_agent) contains "youbot"              or
  lower(http.user_agent) contains "timpibot"            or
  lower(http.user_agent) contains "omgili"              or
  lower(http.user_agent) contains "diffbot"             or
  lower(http.user_agent) contains "ccbot"               or
  lower(http.user_agent) contains "ai2bot"              or
  lower(http.user_agent) contains "cohere"              or
  lower(http.user_agent) contains "duckassistbot"       or
  lower(http.user_agent) contains "bytespider"          or
  lower(http.user_agent) contains "applebot"            or
  lower(http.user_agent) contains "google-extended"     or
  lower(http.user_agent) contains "anthropic"           or

  (cf.verified_bot_category in {"AI Crawler" "Other"})  or

  (http.user_agent wildcard "*2ip*") or
  (http.user_agent wildcard "*archive.org_bot*") or
  (http.user_agent wildcard "*awariobot*") or
  (http.user_agent wildcard "*barkrowler*") or
  (http.user_agent wildcard "*blexbot*") or
  (http.user_agent wildcard "*bomborabot*") or
  (http.user_agent wildcard "*buck*") or
  (http.user_agent wildcard "*bvbot*") or
  (http.user_agent wildcard "*bytespider*") or
  (http.user_agent wildcard "*ccbot*") or
  (http.user_agent wildcard "*checkhost*") or
  (http.user_agent wildcard "*cincraw*") or
  (http.user_agent wildcard "*claudebot*") or
  (http.user_agent wildcard "*clickagy*") or
  (http.user_agent wildcard "*cocolyzebot*") or
  (http.user_agent wildcard "*criteobot*") or
  (http.user_agent wildcard "*df bot 1.0*") or
  (http.user_agent wildcard "*domainstatsbot*") or
  (http.user_agent wildcard "*domcopbot*") or
  (http.user_agent wildcard "*dotbot*") or
  (http.user_agent wildcard "*globalping*") or
  (http.user_agent wildcard "*gulperbot*") or
  (http.user_agent wildcard "*httrack*") or
  (http.user_agent wildcard "*internet-structure*") or
  (http.user_agent wildcard "*internetmeasurement*") or
  (http.user_agent wildcard "*ioncrawl*") or
  (
    (
      ip.src.asnum in {7224 16509 14618 15169 8075 396982}
      or lower(http.user_agent) contains "crawl"
      or lower(http.user_agent) contains "bot"
      or lower(http.user_agent) contains "spider"
      or lower(http.user_agent) contains "scrapy"
    )
    and not cf.client.bot
    and not (
      (
        cf.verified_bot_category in {"Search Engine Crawler"}
        and (
          lower(http.user_agent) contains "google"
          or lower(http.user_agent) contains "bing"
          or lower(http.user_agent) contains "slurp"
          or lower(http.user_agent) contains "duckduckbot"
          or lower(http.user_agent) contains "cloudflare"
          or lower(http.user_agent) contains "adsbot-google-mobile"
          or lower(http.user_agent) contains "google-adwords"
        )
      )
      or lower(http.user_agent) contains "google-inspectiontool"
      or lower(http.user_agent) contains "google-siteverification"
      or lower(http.user_agent) contains "googlebot"
      or lower(http.user_agent) contains "chrome-lighthouse"
      or lower(http.user_agent) contains "adsbot-google"
      or lower(http.user_agent) contains "google-adwords"
      or lower(http.user_agent) contains "prerender"
      or lower(http.user_agent) contains "headlesschrome"
    )
    and not http.request.uri.path contains "acme-challenge"
  )
)
```

### Part 3 – Block Hackers

This rule blocks bad requests with leaked passwords or empty or strange User‑Agent.
It stops fake referers like "binance.com", "google.com", or "n666888.com" and blocks access to hidden or system files and folders (backup, git, .env, actuator, phpMyAdmin).
It also stops strange path symbols (\ or //) and a special cat API request if IP group and User‑Agent do not match.

**Action:** Block

```plaintext
(cf.waf.credential_check.password_leaked) or
(http.referer eq "binance.com") or
(http.referer eq "google.com") or
(http.referer eq "https://google.com") or
(http.referer eq "bing.com") or
(http.referer eq "https://bing.com") or
(http.referer eq "http://n666888.com") or
(http.request.full_uri eq "https://api.sefinek.net/api/v2/random/animal/cat" and ip.geoip.asnum eq 8075 and http.user_agent eq "python-requests/2.31.0") or
(http.request.uri.path contains "\\") or
(http.request.uri.path eq "/backup") or
(http.request.uri.path eq "/git") or
(http.request.uri.path eq "/old") or
(http.request.uri.path wildcard "*.env*") or
(http.request.uri.path wildcard "*/.*" and not starts_with(http.request.uri.path, "/.well-known/")) or
(http.request.uri.path wildcard "*//*") or
(http.request.uri.path wildcard "*/actuator*") or
(http.request.uri.path wildcard "*/cms*") or
(http.request.uri.path wildcard "*/credentials*") or
(http.request.uri.path wildcard "*/dbadmin*") or
(http.request.uri.path wildcard "*/debug*") or
(http.request.uri.path wildcard "*/env*") or
(http.request.uri.path wildcard "*/etc*") or
(http.request.uri.path wildcard "*/login.action*") or
(http.request.uri.path wildcard "*/phpmyadmin*") or
(http.request.uri.path wildcard "*/readme*") or
(http.request.uri.path wildcard "*/sito*") or
(http.request.uri.path wildcard "*/ssh*") or
(http.request.uri.path wildcard "*/user.action*") or
(http.request.uri.path wildcard "*/webdav*") or
(http.request.uri.path wildcard "*/~adm*") or
(http.request.uri.path wildcard "*/~sysadm*") or
(http.request.uri.path wildcard "*/~webmaster*") or
(http.request.uri.path wildcard "*appsettings*") or
(http.request.uri.path wildcard "*authorized_keys*") or
(http.request.uri.path wildcard "*backup.*") or
(http.request.uri.path wildcard "*config*" and not http.host contains "cdn.") or
(http.request.uri.path wildcard "*docker-compose*") or
(http.request.uri.path wildcard "*dockerfile*") or
(http.request.uri.path wildcard "*dump.*") or
(http.request.uri.path wildcard "*file_put_contents*") or
(http.request.uri.path wildcard "*id_rsa*") or
(http.request.uri.path wildcard "*keys.json*") or
(http.request.uri.path wildcard "*pboot:if*") or
(http.request.uri.path wildcard "*server.key*") or
(http.request.uri.path wildcard "*sftp*") or
(http.request.uri.path wildcard "*wlwmanifest*") or
(http.request.uri.path wildcard "*www-sql*") or
(http.request.uri.path wildcard "*_all_dbs*") or
(http.request.uri.path wildcard "*_debugbar*") or
(http.request.uri.path wildcard "*~ftp*") or
(http.request.uri.path wildcard "*~tmp*") or
(http.request.uri.query wildcard "*.env*") or
(http.request.uri.query wildcard "*etc/passwd*") or
(http.user_agent contains "   ") or
(http.user_agent eq "" and not http.host contains "api." and not http.host contains "cdn." and http.host ne "blocklist.sefinek.net") or
(http.user_agent eq "Mozilla/5.0 (Windows NT 10.0; Win64; x64)") or
(http.user_agent eq "Mozilla/5.0") or
(http.user_agent wildcard "*embeddedbrowser*" and not http.host contains "api." and not http.host contains "cdn.") or
(http.user_agent wildcard "*go-http-client*" and not http.host contains "api." and not http.host contains "cdn." and http.host ne "blocklist.sefinek.net") or
(http.user_agent wildcard "*headless*" and not (lower(http.user_agent) contains "prerender")) or
(http.user_agent wildcard "*mozilla/4.0*") or
(http.user_agent wildcard "*private_keys*") or
(http.user_agent wildcard "*windows 11*")
```

### Part 4 – Block Hackers

This rule stops tools like “curl”, “wget”, “aiohttp”, “python‑requests”, “node” or “okhttp” when they ask for the home page. It also blocks requests for files with extensions such as .log, .py, .sh, .yaml, auth.json or php.ini. It rejects any query that has “..”, “file://”, “php://”, “<?php”, “script>”, “alert(” or other dangerous code patterns.

**Action:** Block

```plaintext
(
  http.user_agent contains "aiohttp" or
  http.user_agent contains "aioquic" or
  http.user_agent contains "curl" or
  http.user_agent contains "okhttp" or
  http.user_agent contains "python-requests" or
  http.user_agent contains "python-httpx" or
  http.user_agent contains "wget"
) and not (
  starts_with(http.host, "api.") or
  starts_with(http.host, "cdn.") or
  http.host eq "blocklist.sefinek.net"
) or
(http.request.uri.path wildcard "*.log*" and not http.host contains "cdn." and http.host ne "blocklist.sefinek.net") or
(http.request.uri.path wildcard "*.py*") or
(http.request.uri.path wildcard "*.sh*" and http.host ne "cdn.sefinek.net") or
(http.request.uri.path wildcard "*.yaml*") or
(http.request.uri.path wildcard "*.yml*") or
(http.request.uri.path wildcard "*auth.json*") or
(http.request.uri.path wildcard "*conf.*") or
(http.request.uri.path wildcard "*crlfinjection*") or
(http.request.uri.path wildcard "*curl%20*") or
(http.request.uri.path wildcard "*curl+*") or
(http.request.uri.path wildcard "*fancyupload*") or
(http.request.uri.path wildcard "*php.ini*") or
(http.request.uri.path wildcard "*phpinfo*") or
(http.request.uri.path wildcard "*phpsysinfo*") or
(http.request.uri.path wildcard "*settings.local*") or
(http.request.uri.path wildcard "*settings.prod*") or
(http.request.uri.path wildcard "*wget%20*") or
(http.request.uri.path wildcard "*wget+*") or
(http.request.uri.query contains "%00") or
(http.request.uri.query contains "%0A") or
(http.request.uri.query contains "%0D") or
(http.request.uri.query contains "%2e%2e") or
(http.request.uri.query contains "..%2f") or
(http.request.uri.query contains "..%5c") or
(http.request.uri.query contains "../") or
(http.request.uri.query contains "..\\") or
(http.request.uri.query contains "squelette=../") or
(http.request.uri.query wildcard "*auto_prepend_file*") or
(http.request.uri.query wildcard "*crlfinjection*") or
(http.request.uri.query wildcard "*curl%20*") or
(http.request.uri.query wildcard "*curl+*") or
(http.request.uri.query wildcard "*ed25519*") or
(http.request.uri.query wildcard "*file://*") or
(http.request.uri.query wildcard "*php://*") or
(http.request.uri.query wildcard "*secrets.json*") or
(http.request.uri.query wildcard "*set-cookie:*") or
(http.request.uri.query wildcard "*wget%20*") or
(http.request.uri.query wildcard "*wget+*") or
(http.user_agent wildcard "*alittle client*") or
(http.user_agent wildcard "*example.com*") or
(http.user_agent wildcard "*php7.4-global*") or
(http.request.uri.query contains ")/*") or 
(http.request.uri.query contains ")--") or 
(http.request.uri.query contains "benchmark(") or 
(http.request.uri.query contains "'0:0:20'") or (
http.request.uri.query contains "MD5(") or 
(http.request.uri.query contains "%22") or 
(http.request.uri.query contains "%20/*") or 
(http.request.uri.query contains "%20--") or 
(http.request.uri.query contains "%20%23") or 
(http.request.uri.query contains ")%23") or (
http.request.uri.query contains "script>") or 
(http.request.uri.query contains "%40") or 
(http.request.uri.query contains "%00") or 
(http.request.uri.query contains "<?php") or 
(http.request.uri.query contains "0x00") or 
(http.request.uri.query contains "0x08") or 
(http.request.uri.query contains "0x09") or 
(http.request.uri.query contains "0x0a") or 
(http.request.uri.query contains "0x0d") or 
(http.request.uri.query contains "0x1a") or 
(http.request.uri.query contains "0x22") or 
(http.request.uri.query contains "0x25") or 
(http.request.uri.query contains "0x27") or 
(http.request.uri.query contains "0x5c") or 
(http.request.uri.query contains "0x5f") or 
(http.request.uri.query contains "0x50") or 
(http.request.uri.query contains "0x3e") or 
(http.request.uri.query contains "<img") or 
(http.request.uri.query contains "<image") or 
(http.request.uri.query contains "document.cookie") or 
(http.request.uri.query contains "onerror()") or 
(http.request.uri.query contains "alert(") 
```

### Part 5 – Deprecated browsers, etc.

This rule stops requests that look unsafe or very old. It blocks any request with a referer that has "http://" from another site, unless it is "localhost" or "127.0.0.1". It also blocks a specific upload URL on sefinek.net. It does not allow requests for any ".php" files except "clientarea.php", and it blocks access to WordPress admin ("wp-admin") and includes ("wp-includes") folders. It also rejects requests from very old browsers and bots by checking for old versions of Chrome, Firefox, Internet Explorer, Android 8, Symbian, Mac OS X 10.9 and similar user‑agent strings.

**Action:** Block

```plaintext
(
  (http.referer contains "http://" and not http.referer contains "localhost" and not http.referer contains "127.0.0.1")
  or (http.request.uri.path wildcard "*.php*" and not http.request.uri.path contains "/clientarea.php")
  or (http.request.uri.path wildcard "*/wp-admin*")
  or (http.request.uri.path wildcard "*/wp-content*")
  or (http.request.uri.path wildcard "*/wp-includes*")
  or (http.user_agent contains "Windows NT 5" and not http.user_agent contains "(via ggpht.com GoogleImageProxy)")
  or (http.user_agent wildcard "*android 8*")

  or (http.user_agent wildcard "*chrome/101.*")
  or (http.user_agent wildcard "*chrome/103.*")
  or (http.user_agent wildcard "*chrome/104.*")
  or (http.user_agent wildcard "*chrome/112.*")
  or (http.user_agent wildcard "*chrome/113.*")
  or (http.user_agent wildcard "*chrome/114.*")
  or (http.user_agent wildcard "*chrome/118.*")
  or ((http.user_agent wildcard "*chrome/119.*") and ip.geoip.asnum ne 14618)
  or (http.user_agent wildcard "*chrome/120.*")
  or (http.user_agent wildcard "*chrome/122.*")
  or (http.user_agent wildcard "*chrome/17.*")
  or (http.user_agent wildcard "*chrome/30.*")
  or (http.user_agent wildcard "*chrome/31.*")
  or (http.user_agent wildcard "*chrome/32.*")
  or (http.user_agent wildcard "*chrome/33.*")
  or (http.user_agent wildcard "*chrome/34.*")
  or (http.user_agent wildcard "*chrome/35.*")
  or (http.user_agent wildcard "*chrome/36.*")
  or (http.user_agent wildcard "*chrome/37.*")
  or (http.user_agent wildcard "*chrome/38.*")
  or (http.user_agent wildcard "*chrome/39.*")
  or (http.user_agent wildcard "*chrome/41.*")
  or (http.user_agent wildcard "*chrome/42.*")
  or (http.user_agent wildcard "*chrome/44.*")
  or (http.user_agent wildcard "*chrome/48.*")
  or (http.user_agent wildcard "*chrome/49.*")
  or (http.user_agent wildcard "*chrome/52.*")
  or (http.user_agent wildcard "*chrome/53.*")
  or (http.user_agent wildcard "*chrome/58.*")
  or (http.user_agent wildcard "*chrome/59.*")
  or (http.user_agent wildcard "*chrome/60.*")
  or (http.user_agent wildcard "*chrome/61.*")
  or (http.user_agent wildcard "*chrome/62.*")
  or (http.user_agent wildcard "*chrome/64.*")
  or (http.user_agent wildcard "*chrome/65.*")
  or (http.user_agent wildcard "*chrome/67.*")
  or (http.user_agent wildcard "*chrome/68.*")
  or (http.user_agent wildcard "*chrome/69.*")
  or (http.user_agent wildcard "*chrome/71.*")
  or (http.user_agent wildcard "*chrome/73.*")
  or ((http.user_agent wildcard "*chrome/74.*") and not http.user_agent contains "Better Uptime Bot")
  or (http.user_agent wildcard "*chrome/77.*")
  or (http.user_agent wildcard "*chrome/78.*")
  or (http.user_agent wildcard "*chrome/79.*")
  or (http.user_agent wildcard "*chrome/80.*")
  or (http.user_agent wildcard "*chrome/81.*")
  or (http.user_agent wildcard "*chrome/83.*")
  or (http.user_agent wildcard "*chrome/84.*")
  or (http.user_agent wildcard "*chrome/85.*")
  or (http.user_agent wildcard "*chrome/86.*")
  or (http.user_agent wildcard "*chrome/87.*")
  or (http.user_agent wildcard "*chrome/88.*")
  or (http.user_agent wildcard "*chrome/89.*")
  or (http.user_agent wildcard "*chrome/91.*")
  or (http.user_agent wildcard "*chrome/92.*")
  or (http.user_agent wildcard "*chrome/93.*")
  or (http.user_agent wildcard "*chrome/94.*")
  or (http.user_agent wildcard "*chrome/95.*")
  or (http.user_agent wildcard "*chrome/96.*")
  or (http.user_agent wildcard "*chrome/97.*")
  or (http.user_agent wildcard "*chrome/98.*")
  or (http.user_agent wildcard "*crios/121.*")
  or (http.user_agent wildcard "*firefox/45.*")
  or (http.user_agent wildcard "*firefox/52.*")
  or (http.user_agent wildcard "*firefox/57.*")
  or (http.user_agent wildcard "*firefox/62.*")
  or (http.user_agent wildcard "*firefox/76.*")
  or (http.user_agent wildcard "*html5plus*")
  or (http.user_agent wildcard "*msie*")
  or (http.user_agent wildcard "*netfront*")
  or (http.user_agent wildcard "*symbianos*")
  or (http.user_agent wildcard "*trident/*")
)
```

<a id="step-2"></a>
## STEP 2 – DDoS L7 Protection & Rate Limiting

Cloudflare has many settings you set yourself. In this guide, we turn on only the ones that protect your server from DDoS attacks. Remember, there are more ways to stop DDoS attacks.

### 1: Creating DDoS L7 Ruleset
<img width="1076" height="556" alt="image" src="https://github.com/user-attachments/assets/a900cc3c-37fb-4b34-9afe-02ff7136c74a" />

#### Security > DDoS > Deploy a DDoS override
1. **Override name:** DDoS L7 ruleset
2. **Ruleset action:** Block
3. **Ruleset sensitivity:** Default

### 2: Rate Limits
<img width="1075" height="561" alt="image" src="https://github.com/user-attachments/assets/53780bff-05d6-42a6-9822-b789bbec69c7" />

#### Security > Rate limiting rules > Create rule
1. **Rule name:** Default rate limit
2. Expression: `(http.request.uri.path eq "/")`
   - **Field:** URI Path
   - **Operator:** starts with
   - **Value:** /
3. When rate exceeds…
   - **Requests:** 1 (protection against HTTP/2 Rapid Reset attack (CVE-2023-44487))
   - **Period:** 10 seconds
4. Then take action…
   - **Choose action:** Block
5. For duration…
   - **Duration:** 10 seconds
   
<a id="step-3"></a>
## STEP 3 – Bot Management

Go to **Security** > **Bots**

<img width="1040" height="822" alt="image" src="https://github.com/user-attachments/assets/9855f668-fd18-443b-bd08-b478016d55c3" />


1. **Bot Fight Mode** - off
2. **Block AI Bots** - Block on all pages
3. **AI Labyrinth** - on
4. **Instruct AI bots to not scrape content** - off

<a id="step-4"></a>
## STEP 4 – Security Headers

1. From your domain dashboard, go to **Rules-** and navigate to **Transform Rules**.
2. On the **Transform Rules page**, select **Modify Response Header**.
3. Click the **Create rule button** to create a new rule.
4. Give the rule a name; here, I will name mine **"Security Header"**.
5. Since I need to apply this rule to **All incoming requests** to my website, I select the first option for the If… section.
6. In the Then… section, I will use Set **static** to set up security headers for my site. Here, I will add **7 recommended security headers**:

<img width="988" height="610" alt="image" src="https://github.com/user-attachments/assets/59dc56ff-29c6-48a4-a7e3-fbce86f02028" />



| Header name                    | Value                                                |
|--------------------------------|------------------------------------------------------|
| cross-origin-opener-policy     | same-origin-allow-popups                             |
| cross-origin-resource-policy   | same-site                                            |
| x-xss-protection               | 1; mode=block                                        |
| strict-transport-security      | max-age=31536000; includeSubDomains; preload         |
| referrer-policy                | no-referrer-when-downgrade                           |
| content-security-policy        | upgrade-insecure-requests; block-all-mixed-content   |
| permissions-policy             | accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=() |

Go to [**securityheaders.com**](https://securityheaders.com/) securityheaders.com to check the result. Here is mine:

<img width="1207" height="315" alt="image" src="https://github.com/user-attachments/assets/75c54d43-f152-4447-9c58-59d68e9fbb91" />




## References

- https://github.com/sefinek/Cloudflare-WAF-Expressions
- https://github.com/V4NT-ORG/Cloudflare-Firewall?tab=readme-ov-file#free-plan
- https://github.com/SocolSRT/cloudflare-rules/tree/main
- https://webagencyhero.com/cloudflare-waf-rules-v3/
- https://4sysops.com/archives/block-ai-scrapers-and-other-web-parasites-with-cloudflare/
- https://algustionesa.com/security-headers/

## [MIT License](LICENSE)
Copyright 2025 © by 5ksana. All Rights Reserved.

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-coff.ee-yellow)](https://coff.ee/bitcoinart)



