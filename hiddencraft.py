#!/usr/bin/env python3
'''
A tool for connecting to minecraft hidden servers.
For more info, look at README.md
'''
from socket import socket, SOL_SOCKET, SO_REUSEADDR
from socket import error as sock_err
import selectors
import torsocks
import sys
import threading
import queue
import logging

MC_PORT = 25565
BUFFSIZE = 4096 #4KB, used in threads

GREEN = '\033[1;32m{}\033[0m'
RED = '\033[1;31m{}\033[0m'

def register_listeners(args):
    '''Creates sockets listening for each hidden service.'''
    selector = selectors.DefaultSelector()
    for offset, arg in enumerate(args):
        try:
            torsocks.onion_check(arg)
        except ValueError:
            print(RED.format(arg), 'not a valid tor domain, ignoring')
        else:
            listener = socket()
            listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', MC_PORT+offset+1))
            listener.listen(1)
            selector.register(listener, selectors.EVENT_READ, data=arg)
            print(
                'listening for connections to',
                GREEN.format(arg),
                'at localhost:%d' % (MC_PORT+offset+1))

    return selector

def my_thread(client, tor, queue_):
    '''Thread for sending data to and from a hidden service.'''
    buff = bytearray(BUFFSIZE)
    bytes_read = 0
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, data=tor)
    selector.register(tor, selectors.EVENT_READ, data=client)
    while True:
        try:
            queue_.get(block=False)
        except queue.Empty:
            pass
        else:
            client.close()
            tor.close()
            return
        for item in selector.select(timeout=0.5):
            key = item[0]
            bytes_read = key.fileobj.recv_into(buff)
            try:
                key.data.sendall(buff[:bytes_read])
            except sock_err:
                queue_.put('die')
                break

def main():
    '''Mainloop'''
    if len(sys.argv) == 1:
        print('Please give at least one tor domain as an argument!')
        sys.exit(1)
    sel = register_listeners(sys.argv[1:])
    threads = []
    try:
        while True:
            for item in sel.select(timeout=0.5):
                key = item[0]
                queue_ = queue.Queue()
                client = key.fileobj.accept()[0]

                try:
                    tor = torsocks.create_connection((key.data, MC_PORT))
                except ValueError as exc:
                    logging.exception(exc)
                    sel.unregister(key.fileobj)
                    continue
                args = (client, tor, queue_)
                thread = threading.Thread(target=my_thread, args=args)
                threads.append((thread, queue_))
                thread.start()
                print('handling connection to', GREEN.format(key.data))
    except KeyboardInterrupt:
        pass
    finally:
        print('\rShutting Down')
        print('killing threads')
        for thread, queue_ in threads:
            if thread.is_alive():
                queue_.put('die')
                thread.join()
        print('closing listeners')
        sock_map = sel.get_map()
        for selector_key in sock_map.values():
            selector_key.fileobj.close()

if __name__ == '__main__':
    main()
