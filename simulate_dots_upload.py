import numpy as np
import pandas as pd
import socket
import json
import time
import struct
import cv2 as cv

UDP_IP = "192.168.43.1"
UDP_PORT = 9090

def snd_bytes(msg):
    sock.sendto(msg, (UDP_IP, UDP_PORT))
    start = time.time()
    try:
        data, server = sock.recvfrom(1024)
        end = time.time()
        elapsed = end - start
        print(f'{unwrap_payload(data.hex())} {elapsed}')
        return data, server
    except socket.timeout:
        print('REQUEST TIMED OUT')

def snd_hex(msg):
    return snd_bytes(bytes.fromhex(msg))

_current_packet = 5
def enum_snd_hex(msg):
    global _current_packet
    _current_packet += 1
    _current_packet %= 256
    preq = "%02x" % _current_packet
    p = wrap_payload(preq+msg)
    snd_hex(p)
    return p

def clear():
    with open("clear.raw", "rb") as clr:
        snd_bytes(clr.read())

def set_brightness(i):
    p = "03 00 C1 02 06 02 00".replace(" ", "")
    p += "%02x" % i
    snd_hex(wrap_payload(p))


def get_json_payloads(json_file):
    with open(json_file, "r") as f:
        jj = json.load(f)

    payloads = []
    for p in jj:
        udp_part = p["_source"]["layers"]["udp"]
        payloads.append(udp_part["udp.payload"].replace(":", ""))
    return payloads

def replay_json(json_file = "LED_Space_captures/upload_4dots_bmp.pcap.json"):
    for payload in get_json_payloads(json_file):
        snd_hex(payload)

def check_payload(payload):
    bts = payload_to_bytes(payload)
    valid = True
    valid &= len(bts[6:])%(1<<16) == 256 * bts[5] + bts[4]
    valid &= sum(bts[:-2])%(1<<16) == 256 * bts[-1] + bts[-2]
    return valid
    

def payload_to_hi_lo(p):
    hi = [a+b for a, b in zip(p[0::4], p[1::4])]
    lo = [a+b for a, b in zip(p[2::4], p[3::4])]
    return hi, lo

def payload_to_dibytes(payload):
    dibytes = [int(hi+lo, 16) for hi, lo in zip(*payload_to_hi_lo(payload))]
    return dibytes

def payload_to_bytes(payload):
    p = payload
    # bts = [int(hi+lo, 16) for hi, lo in zip(p[0::2], p[1::2])]
    bts = bytes.fromhex(p)
    return bts

def i_to_hi_lo(i):
    return (i>>8)%(1<<8), i%(1<<8)

def wrap_payload(p):
    assert len(p)%2==0
    l = len(p)//2 + 2
    hi, lo = i_to_hi_lo(l)
    cs = "%02x%02x" % (lo, hi)
    rp = ("aa55ffff" 
        + cs
        + p
    )
    bts = payload_to_bytes(rp)
    hi, lo = i_to_hi_lo(sum(bts))
    rp += "%02x%02x" % (lo, hi)
    return rp

def unwrap_payload(p):
    return p[12:-4]

def get_img_from_unwrapped(p):
    return p[58:]

pp=[]
def init_image_upload():
    global pp
    pp.append(enum_snd_hex("00c102080200000901010c01001c060300010003000d01001d09000000004000400000"))
    pp.append(enum_snd_hex("00c1020901010c01000d01000e01001403010a00111000010007030501007800400040004000"))

def wrap_image(p, i):
    return "00c1020901010c01000d01000e0100120708" + "%04x" % (i%(1<<16))+ "00000400138200"+ ("04" if i < 7 else "02") + p

def upload_image_hex(p):
    assert len(p) == 15*1024
    init_image_upload()
    for i in range(7):
        pp.append(enum_snd_hex(wrap_image(p[2048*i:(i+1)*2048], i)))
    pp.append(enum_snd_hex(wrap_image(p[-1024:], 7)))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)

def build_image_hex(r_hex, g_hex, b_hex):
    assert len(r_hex) == 1024 * 5
    assert len(g_hex) == 1024 * 5
    assert len(b_hex) == 1024 * 5
    h = ""
    for i in range(0, 1024*5, 1024):
        h += r_hex[i:i+1024]
        h += g_hex[i:i+1024]
        h += b_hex[i:i+1024]
    return h

def get_hex_of_uniform_color_from_bits(color = "10000"): # from most significant to least significant
    assert len(color) == 5
    for b in color:
        assert b in ("0", "1")
    return "".join("f" * 1024 if b == "1" else "0"*1024 for b in color)



def get_hex_from_img(img):
    assert img.shape[0] == 64 and img.shape[1] == 64 and img.shape[2] == 3
    r = b""
    for b in range(5): # the bits from most significant to least significant
        for c in range(3):
            bits = np.zeros((64,64), dtype=np.bool8)
            for x in range(64): # the swipe over all the 64x64 pixels 
                for y in range(64):
                    bits[x,y]=(img[x, y, c] & (1<<(7-b)))
            v = np.packbits(bits, bitorder="little").tobytes()
            r += v
    return r.hex()

def upload_local_image(img_file):
    img_bgr = cv.imread(img_file)
    img = cv.cvtColor(img_bgr, cv.COLOR_BGR2RGB)
    img_hex = get_hex_from_img(img)
    return upload_image_hex(img_hex)

clear()
set_brightness(7)
upload_local_image("FlatPreloaders_PixelBuddha/FlatPreloaders/64x64/Preloader_7/Sprites/PR_7_00028.png")
# upload_local_image("testing_images/testing_bmp/4dots.bmp")

# upload_image_hex(build_image_hex(r_hex, g_hex, "0"*1024 * 5))
