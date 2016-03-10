#!/usr/bin/env python3
import hashlib
import datetime
import sys
import argparse


class MyHash(object):

    def __init__(self):
        self.a, self.b, self.c, self.d = [None] * 4

    def get_hash(self, text):
        self.a, self.b, self.c, self.d = 0x1e9a03da, 0xd3def92f, 0xa07c1cf4, 0x503fc971
        text = bytearray(text.encode())
        origin_length = 8 * len(text)
        while len(text) % 64 != 56:
            text.append(0)
        text += origin_length.to_bytes(8, byteorder='little')
        for index in range(0, len(text), 64):
            part = text[index:index + 64]
            for i in range(0, 64, 4):
                piece = part[i:i+4]
                number = 0
                for x in piece:
                    number <<= 8
                    number += x
                self.a, self.b, self.c, self.d = self.a ^ number, self.b ^ number, self.c ^ number, self.d ^ number
        return '%08x%08x%08x%08x' % (self.a, self.b, self.c, self.d)


def print_message(hash_text, time, size):
        print('Hash: %s\nTime: %s \nText size: %d bytes' % (hash_text, time, int(size) - 49))


def md5(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()


def sha1(data):
    return hashlib.sha1(data.encode('utf-8')).hexdigest()


def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def sha512(data):
    return hashlib.sha512(data.encode('utf-8')).hexdigest()


def my(data):
    my_hash = MyHash()
    return my_hash.get_hash(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Hash function generator.')
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('algorithm', metavar='algorithm', type=str, help='Hashing algorithm.', choices=["md5", "sha1", "sha256", "sha512", "my"])
    group.add_argument("-f", "--file", help="File to hash.", metavar="file", type=str)
    group.add_argument("-t", "--text", help="Text to hash.", metavar="text", type=str)
    args = parser.parse_args()

    if args.file:
        file_name = args.file
        with open(file_name, "r") as my_file:
            data = my_file.read()
        algorithm = args.algorithm
        size = str(sys.getsizeof(data))
        start_time = datetime.datetime.now()
        hash_text = globals()[algorithm](data)
        end_time = datetime.datetime.now()
        time = end_time - start_time
        print_message(hash_text, time, size)

    elif args.text:
        text = args.text
        algorithm = args.algorithm
        size = str(sys.getsizeof(text))
        start_time = datetime.datetime.now()
        hash_text = globals()[algorithm](text)
        end_time = datetime.datetime.now()
        time = end_time - start_time
        print_message(hash_text, time, size)


