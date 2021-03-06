"""
`cirrina` - Opinionated web framework

Implementation of client code.

:license: LGPL, see LICENSE for details
"""

import aiohttp_jrpc
import asyncio

class RPCClient(object):

    def __init__(self, url):
        self.remote = aiohttp_jrpc.Client(url)

    def __getattr__(self, attr):
        async def wrapper(*args, **kw):
            ret = await self.remote.call(attr, {'args': args, 'kw': kw})
            if ret.error:
                if ret.error['code'] == -32602:
                    raise TypeError(ret.error['message'])
            return ret.result

        return wrapper

