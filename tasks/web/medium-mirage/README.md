# BRICS+ CTF 2024 | mirage

## Description

> Faster than rushing B.

## Public archive

- [public/mirage.tar.gz](public/mirage.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

We need to escape CSP restrictions and get the flag from `/flag`. CSP is set only if the cookie `session` is present.

```csharp
if (ctx.GetCookie("session") != null) {
    ctx.SetHeader(
        "Cross-Origin-Resource-Policy", "same-origin"
    );
    ctx.SetHeader(
        "Content-Security-Policy", (
            "sandbox allow-scripts allow-same-origin; " +
            "base-uri 'none'; " +
            "default-src 'none'; " +
            "form-action 'none'; " +
            "frame-ancestors 'none'; " +
            "script-src 'unsafe-inline'; "
        )
    );
}
```

So here is another way: just remove the `session` cookie. But we can't remove it directly using `document.cookie` because `session` is HttpOnly.

The indended solution exploits the bug in `System.Net` cookie parsing:

[System/net/System/Net/cookie.cs#L1033](https://github.com/microsoft/referencesource/blob/51cf7850defa8a17d815b4700b67116e3fa283c2/System/net/System/Net/cookie.cs#L1033):

```csharp
internal CookieToken FindNext(bool ignoreComma, bool ignoreEquals) {
    m_tokenLength = 0;
    m_start = m_index;
    while ((m_index < m_length) && Char.IsWhiteSpace(m_tokenStream[m_index])) {
        ++m_index;
        ++m_start;
    }

    CookieToken token = CookieToken.End;
    int increment = 1;

    if (!Eof) {
        if (m_tokenStream[m_index] == '"') {
            Quoted = true;
            ++m_index;
            bool quoteOn = false;
            while (m_index < m_length) {
                char currChar = m_tokenStream[m_index];
                if (!quoteOn && currChar == '"')
                    break;
                if (quoteOn)
                    quoteOn = false;
                else if (currChar == '\\')
                    quoteOn = true;
                ++m_index;
            }
```

So if the cookie starts with `"` the parser interprets it as a double-quoted cookie. This way of parsing contradicts RFC, so we can exploit it.

Suppose the `Cookie` header looks like this: `a="beb; session=admin; b=ra"`. There are actually 3 different cookies:

```
{
    'a': '"beb',
    'session': 'admin',
    'b': 'ra"'
}
```

But the server would parse this as

```
{
    'a': 'a="beb; session=admin; b=ra"'
}`
```

So the `session` cookie is inserted inside the `a` cookie. In order to place our cookie before `session` we need to set `Path=/xss` because chrome sorts cookies by path values.

Example solver: [solution/solver.py](solution/solver.py)
