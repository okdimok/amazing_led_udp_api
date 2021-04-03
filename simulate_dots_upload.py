import numpy as np
import pandas as pd
import socket
import json
import time
import struct
import cv2 as cv
from math import ceil,floor


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

_current_packet = 4
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
    p = "00 C1 02 06 02 00".replace(" ", "")
    p += i_to_hex(i)
    enum_snd_hex(p)

def delete_image(img_num):
    p = "00 c1 02 08 02".replace(" ", "")
    p += i_to_hex(img_num, 2)
    enum_snd_hex(p)



def get_json_payloads(json_file):
    with open(json_file, "r") as f:
        jj = json.load(f)

    payloads = []
    for p in jj:
        udp_part = p["_source"]["layers"]["udp"]
        payloads.append(udp_part["udp.payload"].replace(":", ""))
    return payloads

def hexdump_json(json_file):
    payloads = get_json_payloads(json_file)
    s = ("\n".join(unwrap_payload(p) for p in payloads))
    with open(json_file + "_hex.log", "w") as f:
        f.write(s)

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

def i_to_hex(i, nbytes=1):
    a = str(2*nbytes)
    return ("%0"+a+"x") % (i % (1<<(8*nbytes)))

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
def init_image_upload(img_num = 0, total_parts = 8, total_frames = 1):
    global pp
    img_num_hex = i_to_hex(img_num)
    pp.append(enum_snd_hex("00c102080200" + img_num_hex + "0901010c01" + img_num_hex + "1c060300010003000d01001d09000000004000400000"))
    if total_frames == 1:
        pp.append(enum_snd_hex("00c1020901010c01" + img_num_hex + "0d01000e01001403010a00111000010007030501007800400040004000"))
    else:
        pp.append(enum_snd_hex("00c1020901010c01" + img_num_hex + "0d01000e01001403010a00110c000100080305" + i_to_hex(total_frames) + "0040004000"))

def wrap_image(p, img_part_num, total_parts=8, img_num = 0):
    img_num_hex = i_to_hex(img_num)
    r = ("00c1020901010c01"
     + img_num_hex 
     + "0d01000e01001207" 
     + i_to_hex(total_parts) 
     + i_to_hex(img_part_num, 2) 
     + "0000040013"
    )

    if len(p) < int("82", 16):
        r += i_to_hex(len(p)//2)
    else:
        r += "82"
        hi, lo = i_to_hi_lo(len(p)//2)
        r += i_to_hex(lo) + i_to_hex(hi)

    r += p
    # if img_part_num < total_parts - 1:
    #     r += "820004"
    # else:
    #     if not frames_lengths:
    #         r += "820002"
    #     else:
    #         if "is_very_short":
    #             r += "04" # means 4 bytes?
    #         else:
    #             r += "820602" # 82 is the code, 0x206 is the size
        
    return r

def frames_lengths_to_hex(frames_lengths=()):
    frames = ""
    for l in frames_lengths:
        l *= 1.25
        l = int(l)
        hi, lo = i_to_hi_lo(l)
        frames += "%02x%02x" % (lo, hi)
    return frames

def upload_image_hex(p, img_num=0):
    one_frame = 15*1024
    msg_len = 2048
    # assert len(p) % one_frame == 0 # wrong assertion due to frames timings in the beginning
    total_frames = floor(len(p) / one_frame) # one has to consider the additional length from the frame times, hence floor
    total_parts = ceil(len(p) / msg_len)
    init_image_upload(img_num, total_parts=total_parts, total_frames=total_frames)
    for i in range(total_parts):
        pp.append(enum_snd_hex(wrap_image(p[msg_len*i:(i+1)*msg_len], img_part_num=i, total_parts=total_parts, img_num=img_num)))

def join_frames_hexes(frames_hexes, frames_lengths=()):
    joined = ""
    joined += frames_lengths_to_hex(frames_lengths)
    joined += "".join(frames_hexes)
    return joined

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

def get_local_image_hex(img_file):
    img = cv.imread(img_file)
    # height, width = img.shape[:2]
    # img = cv.resize(img, (64, 64), interpolation = cv.INTER_AREA)
    img = cv.cvtColor(img, cv.COLOR_BGR2RGB)
    img_hex = get_hex_from_img(img)
    return img_hex

def upload_local_image(img_file, img_num=0):
    img_hex = get_local_image_hex(img_file)
    return upload_image_hex(img_hex, img_num)

if __name__ == "__main__":
    # clear()
    # set_brightness(16)
    # upload_local_image("FlatPreloaders_PixelBuddha/FlatPreloaders/64x64/Preloader_7/Sprites/PR_7_00012.png")
    frames_hexes = []
    frame_lengths = []
    for i in range(59):
        frames_hexes += [get_local_image_hex("FlatPreloaders_PixelBuddha/FlatPreloaders/64x64/Preloader_1/Sprites/PR_1_{:05d}.png".format(i))]
        frame_lengths += [10]
    upload_image_hex(join_frames_hexes(frames_hexes, frame_lengths))
    # upload_local_image("testing_images/testing_png/pattern_1.png", 1)
    # upload_local_image("testing_images/testing_png/pattern_1.png", 2)

    # img = np.ones((64,64,3), dtype=np.uint8) * 10
    # upload_image_hex()

    # hexdump_json("LED_Space_captures/upload_green_gif_upload_red_gif.pcap.json")
    # clear()
    # hexdump_json("LED_Space_captures/upload_r1g2_anim_gif.pcap.json")
    # set_brightness(15)
    # delete_image(0)