#!/usr/bin/env python3
'''
A module for connecting to Tor's socks proxy.
Visit http://en.wikipedia.org/wiki/SOCKS#SOCKS5 for details.
'''
import socket
import re

ONION = re.compile('^[a-z2-7]{16}\.onion$')

def onion_check(host):
    if not isinstance(host, str):
        junk = type(host)
        raise TypeError('host must be a string, you gave me a %s' % junk)
    if not ONION.match(host):
        raise ValueError('host is not a valid .onion')

def create_connection(host_port, tor_host='127.0.0.1', tor_port=9050):
    '''Creates a connection, handling SOCKS5 junk.'''
    host, port = host_port
    onion_check(host)
    try:
        connection = socket.create_connection((tor_host, tor_port))
    except socket.error as exc:
        args = list(exc.args)
        args[1] += '\nmake sure tor is installed and running!'
        args[1] += '\nmaybe try rebooting tor...'
        exc.args = tuple(args)
        raise
    connection.sendall(b'\x05\x01\x00')
    response = connection.recv(2)
    if response != b'\x05\x00':
        error = 'tor gave you junk: %s tor should be listening at %s:%d'
        raise ValueError(error % (response, tor_host, tor_port))
    connect_details = bytearray((5, 1, 0, 3, 22))
    connect_details.extend(host.encode('ascii'))
    connect_details.append(port >> 8)
    connect_details.append(port & 0xFF)
    connection.sendall(connect_details)
    response = connection.recv(10)
    if response != b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00':
        if response[0] != 5: #like wtf, this should never happen
            error = 'this isn\'t a SOCKS5 proxy? lol: %s'
            raise ValueError(error % response)
        errors = (
            'general failure',
            'connection not allowed by ruleset',
            'network unreachable',
            'host unreachable',
            'connection refused by destinaion host',
            'timed out',
            'command not supported',
            'address type not supported',
            )
        for val, error in enumerate(errors):
            if response[1] == (val + 1):
                raise ValueError(error + ': %s'%response)
    return connection

if __name__ == '__main__':
    hidden_wiki = create_connection(('zqktlwi4fecvo6ri.onion', 80))
    hidden_wiki.sendall(b'GET /wiki/index.php/Main_Page HTTP/1.0\r\n\r\n')
    data = bytearray(200000)
    view = memoryview(data)
    bytes_read = 1
    i = 0
    while (bytes_read != 0) and (i < 200000):
        #This loop should terminate... *fingers crossed*
        bytes_read = hidden_wiki.recv_into(view[i:])
        i += bytes_read
        print(bytes_read)
    print(data.decode())
