#!/usr/bin/python3

import asyncio
import aiohttp
from aiohttp_jrpc import Client,InvalidResponse

Remote = Client('http://localhost:8080/jrpc')

@asyncio.coroutine
def rpc_call():
    try:
        rsp = yield from Remote.call('hello', {'data': 'hello'})
        print(rsp)
        yield from asyncio.sleep(1.0)
        rsp = yield from Remote.call('hello', {'data': 'hello'})
        print(rsp)
        yield from asyncio.sleep(1.0)
        rsp = yield from Remote.call('hello', {'data': 'hello'})
        print(rsp)
    except InvalidResponse as err:
        return err
    except Exception as err:
        return err
    return False

loop = asyncio.get_event_loop()
content = loop.run_until_complete(rpc_call())
loop.close()
