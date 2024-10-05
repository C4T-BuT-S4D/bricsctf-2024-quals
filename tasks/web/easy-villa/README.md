# BRICS+ CTF 2024 | villa

## Description

> Have you ever know about the game "King of the Villa"?
> 
> The goal is simple: just become the owner of the villa.
> 
> Good luck.

## Public archive

- [public/villa.tar.gz](public/villa.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

The service is written in [vlang](https://vlang.io/). The handler `GET /villa` reads a template from `villa.html` and renders it using `$vweb.html()`.

There is a SSTI (server-side template injection) in `POST /villa`. The attacker could write the payload in `owner` field, it will be inserted in the file `villa.html` without any sanitization.

The intended solution requires reading the standard library's template engine. The source code is here: [vlib/v/parser/tmpl.v](https://github.com/vlang/v/blob/master/vlib/v/parser/tmpl.v). The engine translates the template into a vlang code and compiles it, therefore there is an RCE vulnerability.

For example the attacker could exploit CSS matcher:

[vlib/v/parser/tmpl.v#L397](https://github.com/vlang/v/blob/715dc3116123b69abe25d14536cad18da6bd7ab6/vlib/v/parser/tmpl.v#L397)

```v
} else if line_t.starts_with('.') && line.ends_with('{') {
    // `.header {` => `<div class='header'>`
    class := line.find_between('.', '{').trim_space()
    trimmed := line.trim_space()
    source.write_string(strings.repeat(`\t`, line.len - trimmed.len)) // add the necessary indent to keep <div><div><div> code clean
    source.writeln('<div class="${class}">')
    continue
}
```

A line between `'.'` and `'{'` is inserted into the template's code without any modification. The simplest way is using `C.system()` function which runs a shell command in a separate process.

Example solver: [solution/solver.py](solution/solver.py)
