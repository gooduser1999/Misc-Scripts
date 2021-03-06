#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Usage::
    ./server.py [<port>]
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import base64
import json
import os
import datetime
import binascii
import zlib
from os import curdir
from optparse import OptionParser
from os.path import join as pjoin
from pathlib import Path

def deflate(data):
    compress = zlib.compressobj(9, zlib.DEFLATED, -15, zlib.DEF_MEM_LEVEL, 0)
    deflated = compress.compress(data)
    deflated += compress.flush()
    return base64.b64encode(deflated)

def inflate(data):
    data = base64.b64decode(data)
    decompress = zlib.decompressobj(-15)
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated

class S(BaseHTTPRequestHandler):
    store_path = pjoin(curdir, 'store.json')        
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            b64_string = post_data
            post_data = inflate(b64_string)
            logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data) #.decode('utf-8'))

        except binascii.Error as err:
            logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))

        path = str(self.path)
        store_path = pjoin(curdir, 'store.json')
        for char in ' /':
            path = path.replace(char,'')
        path = path.replace("store.json", "")
        dirname='/opt/server/Public/'
        filename = path
        path = Path(dirname, filename)
        try:
            log_file = open(path, "wb")
            log_file.write(post_data)
            log_file.close()
            print("Wrote contents to %s." % path)
        except IOError:
            f=open(store_path, "ab+")
            f.write(post_data)
            f.close()
            log_file = open(store_path, "a")
            log_file.write("\n")
            log_file.write("%s\n" % datetime.datetime.now())
            log_file.write("\n")
            log_file.close()
            print("Wrote contents to %s." % store_path)

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=8181):
    logging.basicConfig(level=logging.INFO)
    server_address = ('127.0.0.1', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()


