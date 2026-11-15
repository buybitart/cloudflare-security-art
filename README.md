# Cloudflare's WAF Rules (Free Plan)

**This guide helps you protect your website using Cloudflare's Free Plan. The goal is to make website security simple and reliable with WAF rules, DDoS protection, security headers, and bot settings.**

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
See [**Is AI the greatest art heist in history?**](https://www.theguardian.com/books/2026/apr/12/is-ai-the-greatest-art-heist-in-history) and [**‘Mass theft’: Thousands of artists call for AI art auction to be cancelled**](https://www.theguardian.com/technology/2025/feb/10/mass-theft-thousands-of-artists-call-for-ai-art-auction-to-be-cancelled) 
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
> 
> In 2024, OpenAI’s chief technology officer Mira Murati told an interviewer that the creative jobs destroyed by her company’s product maybe “shouldn’t have been there in the first place”.

AI pretend to be search engines, but they don't bring you visitors.  
Some even use fake user agents, so basic Cloudflare settings may not stop them.
This rule blocks **all** bots by default, and then **only allows useful bots** that help your website get indexed.
I highly recommend reading [Block AI scrapers with Cloudflare](https://4sysops.com/archives/block-ai-scrapers-and-other-web-parasites-with-cloudflare/).

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

<img width="1218" height="414" alt="image" src="https://github.com/user-attachments/assets/eb805c9e-81b6-4fd0-ba93-538cecef55c3" />



### Part 1 – Block Bot Parasites

The Cloudflare rule I provide below will block not just AI scrapers but all web parasites that suck traffic from your site. This is achieved by applying a Zero Trust approach, which assumes all crawlers are harmful and only explicitly permits those that are useful for your organization.

> NOTE🔒 **This rule stops about 90% of all threats. It cuts off bad bot traffic before it reaches the application.**

**Action:** Block

```plaintext

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
or (
  ip.src.asnum in {135061 23724 4808}
  and http.user_agent contains "siteaudit"
)
or (
  http.host contains ":80"
)
or (
  http.host contains ":443"
)
or (
  http.cookie contains "cf_use_ob="
  and not http.cookie contains "0"
  and not http.cookie contains "80"
  and not http.cookie contains "443"
  and not cf.client.bot
)
or 

(
  (
    (
      cf.client.bot
      or http.request.version in {"HTTP/1.0" "HTTP/1.1"}
      or ip.src.asnum in {7224 16509 14618 15169 8075 396982}
      or lower(http.user_agent) contains "crawl"
      or lower(http.user_agent) contains "bot"
      or lower(http.user_agent) contains "spider"
      or lower(http.user_agent) contains "scrapy"
    )
    and not (
      cf.verified_bot_category in {
        "Search Engine Crawler"
        "Page Preview"
        "Security"
      }
      and (
        lower(http.user_agent) contains "google"
        or lower(http.user_agent) contains "bing"
        or lower(http.user_agent) contains "slurp"
        or lower(http.user_agent) contains "duckduckbot"
        or lower(http.user_agent) contains "cloudflare"
        or lower(http.user_agent) contains "google-inspectiontool"
        or lower(http.user_agent) contains "google-siteverification"
        or lower(http.user_agent) contains "telegram"
        or lower(http.user_agent) contains "googlebot"
        or lower(http.user_agent) contains "chrome-lighthouse"
        or lower(http.user_agent) contains "adsbot-google"
        or lower(http.user_agent) contains "google-adwords"
        or lower(http.user_agent) contains "let's encrypt"
        or lower(http.request.uri.path) contains "acme-challenge"
        or lower(http.request.uri.path) contains "pki-validation"
      )
    )
  )
  or (
    not cf.edge.server_port in {80 443}
  )
)

```

### Part 2 – Block AI and Bad Crawlers

Blocks known AI bots and web scrapers, including GPTBot, ClaudeBot, and Bytespider. Also blocks Cloudflare-verified bots in the AI Crawler and Other categories.
There are clearly many other AI crawlers that you don’t want to steal your content. Additionally, Cloudflare categorizes bots from Perplexity or OpenAI’s SearchGPT as search engine crawlers. However, don’t expect noteworthy traffic to your website from these so-called answering machines. These are certainly not search engines. As their name suggests, they are not intended to drive traffic to your site.

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
  (http.user_agent wildcard "*ioncrawl*") 
)

```

### Part 3 – Block Hackers

Blocks requests for private files, backups, admin pages, and configuration files.
Also blocks leaked-password attempts and suspicious User-Agent values.

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

Blocks tools like curl, wget, and Python HTTP clients, with some host exceptions.
Also blocks requests for sensitive files and URLs with common attack patterns.

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

### Part 5 – Part 5 -  Challenge Not Bot Risk Traffic


**Action:** Managed Challenge

While legitimate users do use VPNs, hackers and spammers often use them too. In my experience, malicious traffic causes more problems than these restrictions. That's why I use Cloudflare Managed Challenge for VPN providers and countries or continents where I see high bot activity.

```plaintext
not cf.client.bot
and (
  (ip.src.asnum in {60068 9009 16247 51332 212238 131199 22298 29761 62639 206150 210277 46562 8100 3214 206092 206074 206164 213074})
  or ip.src.continent in {"NA" "OC" "SA" "T1" "AF" "AN" "AS"}
  or ip.src.country in {
    "DE" "NL" "FR" "GB" "IE" "FI" "LU" "BE" "BY" "AL" "XK"
    "RS" "BG" "UA" "SK" "RO" "MD" "HU" "MT" "HR" "ME" "IT" "RU"
  }
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
   - **Operator:** equals
   - **Value:** /
3. When rate exceeds…
   - **Requests:** 2 (protection against HTTP/2 Rapid Reset attack (CVE-2023-44487))
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
