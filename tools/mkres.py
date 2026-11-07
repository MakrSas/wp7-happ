#!/usr/bin/env python3
"""
Пишет <Assembly>.g.resources (формат .resources v2) с XAML-страницами как потоками —
так их ищет Application.LoadComponent. Заголовок ссылается на mscorlib Silverlight 2.0.5.0,
иначе ResourceManager на телефоне не примет файл.

  mkres.py out.resources key=path ...   (key — путь в нижнем регистре, например pages/mainpage.xaml)
"""
import struct
import sys

READER = "System.Resources.ResourceReader, mscorlib, Version=2.0.5.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e"
RESSET = "System.Resources.RuntimeResourceSet"
TYPE_STREAM = 0x21


def str7(b):
    """BinaryWriter.Write(string): 7-битная длина + байты."""
    out = bytearray()
    n = len(b)
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out) + b


def name_hash(s):
    h = 5381
    for ch in s:
        h = (((h << 5) + h) & 0xFFFFFFFF) ^ ord(ch)
    return struct.unpack("<i", struct.pack("<I", h))[0]


def main():
    out = sys.argv[1]
    items = []
    for arg in sys.argv[2:]:
        key, path = arg.split("=", 1)
        with open(path, "rb") as f:
            items.append((key, f.read()))

    header = str7(READER.encode()) + str7(RESSET.encode())
    buf = bytearray()
    buf += struct.pack("<iii", 0xBEEFCACE - (1 << 32), 1, len(header)) + header
    buf += struct.pack("<iii", 2, len(items), 0)  # версия, ресурсов, типов
    while len(buf) % 8:
        buf += b"PAD"[len(buf) % 3:len(buf) % 3 + 1]

    names = bytearray()
    data = bytearray()
    entries = []
    for key, blob in items:
        entries.append((name_hash(key), len(names)))
        names += str7(key.encode("utf-16-le")) + struct.pack("<i", len(data))
        data += bytes([TYPE_STREAM]) + struct.pack("<i", len(blob)) + blob
    entries.sort(key=lambda e: e[0])

    for h, _ in entries:
        buf += struct.pack("<i", h)
    for _, pos in entries:
        buf += struct.pack("<i", pos)
    data_offset = len(buf) + 4 + len(names)
    buf += struct.pack("<i", data_offset) + names + data

    with open(out, "wb") as f:
        f.write(buf)
    print("mkres:", out, len(items), "ресурсов,", len(buf), "байт")


if __name__ == "__main__":
    main()
