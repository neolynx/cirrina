#!/usr/bin/python3

import asyncio
import aiohttp
from aiohttp_jrpc import Client,InvalidResponse
import sys

Remote = Client('http://localhost:8080/jrpc')

sys.stdout.write("Send: ")
msg = input().strip()

@asyncio.coroutine
def rpc_call(msg):
    try:
        rsp = yield from Remote.call('hello', {'data': msg})
        print(rsp)
    except InvalidResponse as err:
        return err
    except Exception as err:
        return err
    return False

loop = asyncio.get_event_loop()
content = loop.run_until_complete(rpc_call(msg))
loop.close()
