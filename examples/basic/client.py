import asyncio
from aiohttp_jrpc import InvalidResponse
from cirrina import RPCClient
import sys

remote = RPCClient('http://localhost:8080/jrpc')

sys.stdout.write("Send: ")
msg = input().strip()

@asyncio.coroutine
def rpc_call(msg):
    try:
        rsp = yield from remote.hello(msg, 7, debug=True)
        print("Got:", rsp)
    except InvalidResponse as err:
        return err
    except Exception as err:
        return err
    return False

loop = asyncio.get_event_loop()
content = loop.run_until_complete(rpc_call(msg))
loop.close()
