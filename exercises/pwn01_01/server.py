#!/usr/bin/env python3
import dataclasses
import random
import string
import asyncio
import logging
import subprocess

import ast
from asyncio import StreamReader, StreamWriter
from typing import TypeVar, Callable

from pwn_utils import utils
from pwn_utils.utils import read_line_safe

log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)


def accept_client(client_reader: StreamReader, client_writer: StreamWriter):
    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info('connection closed')

    task.add_done_callback(client_done)


async def handle_client(client_reader: StreamReader, client_writer: StreamWriter):
    try:
        remote = client_writer.get_extra_info('peername')
        if remote is None:
            log.error('Could not get ip of client')
            return
        remote = '%s:%s' % (remote[0], remote[1])
        log.info('new connection from: %s' % remote)
    except Exception as e:
        log.error('EXCEPTION (get peername): %s (%s)' % (e, type(e)))
        return

    try:
        client_writer.write('Please enter username:\n'.encode())
        await client_writer.drain()
        username = await read_line_safe(client_reader)
        if username != 'admin':
            client_writer.write('Invalid username\n'.encode())
            await client_writer.drain()
            return
        client_writer.write('Please enter password:\n'.encode())
        await client_writer.drain()

        password = await read_line_safe(client_reader)
        if password != 'password':
            client_writer.write('Invalid password\n'.encode())
            await client_writer.drain()
            return
        client_writer.write('Welcome admin\n'.encode())
        await client_writer.drain()
        flag = subprocess.check_output('flag')
        client_writer.write(flag)
        await client_writer.drain()
    except Exception as e:
        utils.log_error(e, client_writer)


def main():
    # start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20001)
    log.info('Server waiting for connections')
    loop.run_until_complete(f)
    loop.run_forever()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s',
    )

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
