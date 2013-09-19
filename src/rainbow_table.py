#!/usr/bin/env python

from hashlib import sha1
from random import SystemRandom
sr = SystemRandom()

charset  = [chr(b) for b in xrange(ord('a'), ord('z')+1)] 
charset += [chr(b) for b in xrange(ord('A'), ord('Z')+1)]
charset += [chr(b) for b in xrange(ord('0'), ord('9')+1)]
charset += [' ', '!']

k = 250

def xor(s1, s2):
    l = map(lambda tup: ord(tup[0])^ord(tup[1]), zip(s1, s2))
    return ''.join(map(lambda b: chr(b), l))

def H(p):
    return sha1(p).digest()

_R_xor_cache = {}

def R(h, n):
    assert type(h) is str
    assert len(h) == 20
    global _R_xor_cache

    if not _R_xor_cache.has_key(n):
        _R_xor_cache[n] = H(str(n)+'blah')
    xorval = _R_xor_cache[n]
    xored_h = xor(h, xorval)
    
    #  remember, our passwords are exactly 6 chars long, chosen from the charset global variable
    assert len(charset) == 64
    _p = map(lambda c: charset[ord(c)&0x3f], xored_h[:6])
    p = ''.join(_p)
    return p


def rand_pass():
    global sr
    return R_fast(H(hex(sr.getrandbits(64))), 1)


def gen_chain():
    p_first = rand_pass()
    p = p_first
    for n in xrange(1, k+1):    # 1-based, not 0-based!
        h = H(p)
        p = R_fast(h, n)
    p_last = p
    return (p_first, p_last)


table = {}

def build_table(num_entries):
    global table    # adds to this: hash of p_last => (p_first, p_last)
    for i in xrange(num_entries):
        chain = gen_chain()
        p_last = chain[1]
        table[p_last] = chain

def crack(h):
    """returns p (the password) that generates hash h if possible; otherwise
    return the number of times chains were found in the table (i.e., the number
    of false positives"""
    global table
    # find a chain that p is in; otherwise, fail
    chain = None
    chains_found = 0
    for i in xrange(k, 0, -1):     # count from k down to 1
        _h = h
        for j in xrange(i, k+1):
            if j > i:       # not the first time
                _h = H(p)
            p = R(_h, j)
        if table.has_key(p):
            chain = table[p]
            chains_found += 1
            # a chain was found; now, find p in the chain
            p = chain[0]
            for n in xrange(1, k+1):
                _h = H(p)
                if _h == h:    # found it!
                    return p
                p = R(_h, n)

    return chains_found    # not found

