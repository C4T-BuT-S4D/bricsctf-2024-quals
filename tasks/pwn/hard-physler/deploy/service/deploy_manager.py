#!/usr/bin/env python3
import os
import sys
import subprocess
import requests
import time
import shutil

from hashlib import sha256
from binascii import unhexlify, hexlify
from base64 import b64decode, b64encode

DELETE_TIME = 120

def download_file(url):
    try:
        resp = requests.get(url, timeout=5)
    except:
        print("[-] Can't downlaod file! Some internal error! Check your URL and contact with admin!")
        exit(0)

    if resp.status_code != 200:
        print("[!] Can't download file! Status code: {}".format(resp.status_code))
        exit(0)

    if len(resp.content) > (2 * 1024 * 1024):
        print("[-] Size of binary is incorrect!")
        exit(0)

    return resp.content

def run_cmd(cmd, cur_dir):
    subprocess.run(cmd, shell=True, cwd=cur_dir)

def gen_pow():
    prefix = hexlify(os.urandom(4)).decode()
    rnd_bytes = hexlify(os.urandom(3)).decode()
    return prefix, rnd_bytes

def sorted_ls(path):
    files = os.listdir(path)
    retfiles = []

    for file_path in files:
        last_mod_time = os.path.getmtime(path + file_path)
        current_time = time.time()

        if current_time - last_mod_time > DELETE_TIME and file_path.startswith("qemu_"):
            retfiles.append(path + file_path)

    return retfiles

def remove_old_dirs():
    files = sorted_ls("/tmp/")
    for i in files:
        shutil.rmtree(i, ignore_errors=True)

def main():
    # generate POW
#    prefix, correct = gen_pow()
#    user_answer = input("Prefix: {}\nsha256(Prefix + POW)[:6] == {}\n[?] POW: ".format(prefix, correct))

#    if sha256(prefix.encode() + user_answer.strip().encode()).hexdigest()[:6] != correct:
#        print("[-] Incorrect POW!")
#        exit(0)

    remove_old_dirs()

    link_to_user_exploit = input("[?] Enter external-link to your exploit (e.g https://paste.c-net.org/ or other, max size: 2Mb): ").strip()
    data = download_file(link_to_user_exploit)

    rnd_dir = hexlify(os.urandom(8)).decode()
    rnd_fname = hexlify(os.urandom(16)).decode()

    tmp_filename = '/tmp/qemu_inst_{}/user_exploit_{}'.format(rnd_dir, rnd_fname)
    tmp_dirname = '/tmp/qemu_inst_{}'.format(rnd_dir)
    os.mkdir(tmp_dirname)

    fd = open(tmp_filename, 'wb')
    fd.write(data)
    fd.close()

    os.chdir(tmp_dirname)

    # copy template of initramfs, unpack, add user-exploit file, pack
    run_cmd("cp /task/fs/* .", tmp_dirname)
    run_cmd("./decompress.sh", tmp_dirname)
    run_cmd("echo $FLAG > ./initramfs/root/flag.txt", tmp_dirname)
    run_cmd("cp {} ./initramfs/exploit".format(tmp_filename, tmp_dirname), tmp_dirname)
    run_cmd("chmod ugo+x ./initramfs/exploit", tmp_dirname)
    run_cmd("./compr.sh", tmp_dirname)
    run_cmd("rm -rf ./initramfs/", tmp_dirname)
    run_cmd("rm -rf {}".format("user_exploit_{}".format(rnd_fname)), tmp_dirname)
    run_cmd('timeout 60 ./run.sh', tmp_dirname)
    run_cmd("rm -rf {}".format(tmp_dirname), "/")

if __name__ == "__main__":
    main()
