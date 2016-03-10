#!/usr/bin/python3
from gi.repository import Gtk
import hashlib
import datetime
import sys


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


class MyBuilder(Gtk.Builder):

    def __init__(self):
        Gtk.Builder.__init__(self)
        self.add_from_file("ui.glade")

        handlers = {
            "generate": self.generate
        }
        self.connect_signals(handlers)

        self.window = self.get_object("main_window")
        self.md5_button = self.get_object("radiobutton_md5")
        self.sha1_button = self.get_object("radiobutton_sha1")
        self.sha256_button = self.get_object("radiobutton_sha256")
        self.sha512_button = self.get_object("radiobutton_sha512")
        self.my_button = self.get_object("radiobutton_moj")
        self.textview1 = self.get_object("textview1")
        self.textview2 = self.get_object("textview2")
        self.button1 = self.get_object("button1")

        self.md5_button.set_active(True)
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.show_all()

    def get_text(self):
        buffer = self.textview1.get_buffer()
        start_iter = buffer.get_start_iter()
        end_iter = buffer.get_end_iter()
        return buffer.get_text(start_iter, end_iter, False)

    def get_algorithm(self):
        if self.md5_button.get_active():
            return "md5"
        elif self.sha1_button.get_active():
            return "sha1"
        elif self.sha256_button.get_active():
            return "sha256"
        elif self.sha512_button.get_active():
            return "sha512"
        elif self.my_button.get_active():
            return "my"

    @staticmethod
    def md5(text):
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha1(text):
        return hashlib.sha1(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha256(text):
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha512(text):
        return hashlib.sha512(text.encode('utf-8')).hexdigest()

    @staticmethod
    def my(text):
        my_hash = MyHash()
        return my_hash.get_hash(text)

    def generate(self, widget):
        text = self.get_text()
        algorithm = self.get_algorithm()
        method = getattr(self, algorithm)
        size = str(sys.getsizeof(text))
        start_time = datetime.datetime.now()
        hash_text = method(text)
        end_time = datetime.datetime.now()
        delta = end_time - start_time
        self.set_message(hash_text, str(delta.microseconds), size)

    def set_message(self, hash_text, time, size):
        self.textview2.get_buffer().set_text(
            'Hash: %s\nTime: %s microseconds\nText size: %d bytes' % (hash_text, time, int(size) - 49))

    def clear_message(self):
        self.textview2.get_buffer().set_text("")


if __name__ == "__main__":
    program = MyBuilder()
    Gtk.main()
