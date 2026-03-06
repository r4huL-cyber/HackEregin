#!/usr/bin/env python3

import base64
import codecs
import string
import urllib.parse
import html
import os
import time
from termcolor import cprint

# ==============================
# Banner
# ==============================

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')

    banner_text = r"""
   _   _           _     _____                _
  | | | | __ _ ___| |__ | ____|_ __ ___  __ _(_)_ __
  | |_| |/ _` / __| '_ \|  _| | '__/ _ \/ _` | | '_ \
  |  _  | (_| \__ \ | | | |___| | |  __/ (_| | | | | |
  |_| |_|\__,_|___/_| |_|_____|_|  \___|\__, |_|_| |_|
                                        |___|

                                by r4hul-cyb3r
                ⚡ Universal Encoding & Cipher Detector ⚡
    """

    cprint(banner_text,"cyan",attrs=["bold"])


# ==============================
# English scoring
# ==============================

COMMON_WORDS = ["the","and","flag","ctf","hello","password","admin"]

def english_score(s):
    s = s.lower()
    score = sum(s.count(w) for w in COMMON_WORDS)
    return score


# ==============================
# Hash detection
# ==============================

def is_hash(s):

    if all(c in string.hexdigits for c in s):

        if len(s)==32:
            return "MD5"

        if len(s)==40:
            return "SHA1"

        if len(s)==64:
            return "SHA256"

        if len(s)==128:
            return "SHA512"

    return None


# ==============================
# Decoders
# ==============================

def try_base64(s):
    try:
        s += "=" * (-len(s)%4)
        return base64.b64decode(s).decode("utf-8","ignore")
    except:
        return None


def try_base32(s):
    try:
        return base64.b32decode(s).decode("utf-8","ignore")
    except:
        return None


def try_base85(s):
    try:
        return base64.b85decode(s).decode("utf-8","ignore")
    except:
        return None


def try_base58(s):

    alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    try:
        num=0
        for c in s:
            num=num*58+alphabet.index(c)

        decoded=num.to_bytes((num.bit_length()+7)//8,'big')

        return decoded.decode("utf-8","ignore")

    except:
        return None


def try_hex(s):
    try:
        s=s.replace(" ","")
        return bytes.fromhex(s).decode("utf-8","ignore")
    except:
        return None


def try_binary(s):

    try:
        s=s.replace(" ","")
        if len(s)%8!=0:
            return None

        decoded="".join(
            chr(int(s[i:i+8],2))
            for i in range(0,len(s),8)
        )

        return decoded

    except:
        return None


def try_url(s):

    decoded=urllib.parse.unquote_plus(s)

    if decoded!=s:
        return decoded

    return None


def try_html(s):

    decoded=html.unescape(s)

    if decoded!=s:
        return decoded

    return None


def try_rot13(s):

    decoded=codecs.decode(s,"rot_13")

    if decoded!=s:
        return decoded

    return None


def try_rot5(s):

    table=str.maketrans(
        "0123456789",
        "5678901234"
    )

    decoded=s.translate(table)

    if decoded!=s:
        return decoded

    return None


def try_rot18(s):

    result=""

    for c in s:

        if c.isalpha():
            result+=codecs.decode(c,"rot_13")

        elif c.isdigit():
            result+=str((int(c)+5)%10)

        else:
            result+=c

    if result!=s:
        return result

    return None


def try_atbash(s):

    result=""

    for c in s:

        if c.islower():
            result+=chr(122-(ord(c)-97))

        elif c.isupper():
            result+=chr(90-(ord(c)-65))

        else:
            result+=c

    if result!=s:
        return result

    return None


def try_reverse(s):

    decoded=s[::-1]

    if decoded!=s:
        return decoded

    return None


# Morse dictionary
MORSE = {
'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E',
'..-.':'F','--.':'G','....':'H','..':'I','.---':'J',
'-.-':'K','.-..':'L','--':'M','-.':'N','---':'O',
'.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T',
'..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y',
'--..':'Z','/':' '
}

def try_morse(s):

    try:
        words=s.split(" ")

        decoded="".join(MORSE.get(w,"") for w in words)

        if decoded:
            return decoded.lower()

    except:
        pass

    return None


# ==============================
# Detection Engine
# ==============================

def detect(text):

    methods=[

    ("Base64",try_base64),
    ("Base32",try_base32),
    ("Base85",try_base85),
    ("Base58",try_base58),

    ("Hex",try_hex),
    ("Binary",try_binary),

    ("URL Encoding",try_url),
    ("HTML Entities",try_html),

    ("ROT13",try_rot13),
    ("ROT5",try_rot5),
    ("ROT18",try_rot18),

    ("Atbash Cipher",try_atbash),
    ("Caesar / ROT13",try_rot13),

    ("Reverse",try_reverse),
    ("Morse Code",try_morse)

    ]


    results=[]

    for name,func in methods:

        decoded=func(text)

        if decoded:

            score=english_score(decoded)

            results.append(
                (name,decoded,score)
            )


    results.sort(
        key=lambda x:x[2],
        reverse=True
    )

    return results


# ==============================
# Main
# ==============================

def main():

    banner()

    text=input("\n🔹 Paste encoded text: ").strip()

    print("\n🔎 Detecting methods...\n")

    time.sleep(0.3)


    hash_type=is_hash(text)

    if hash_type:

        cprint(f"[!] Detected Hash: {hash_type}","yellow")

        return


    results=detect(text)

    if not results:

        cprint("No decoding detected.","red")

        return


    for i,(method,decoded,score) in enumerate(results[:5],1):

        cprint(
            f"{i}. {method}",
            "cyan",
            attrs=["bold"]
        )

        print("   →",decoded,"\n")


# ==============================

if __name__=="__main__":
    main()
