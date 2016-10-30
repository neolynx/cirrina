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
        ret = yield from remote.hello(msg, 7, debug=True)
        return ret
    except InvalidResponse as err:
        return err
    except Exception as err:
        return err
    return False

loop = asyncio.get_event_loop()
ret = loop.run_until_complete(rpc_call(msg))
print("Got:", ret)
loop.close()
