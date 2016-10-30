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
        if attr == '__init__':
            return __init__

        @asyncio.coroutine
        def wrapper(*args, **kw):
            ret = yield from self.remote.call(attr, {'args': args, 'kw': kw})
            return ret

        return wrapper

