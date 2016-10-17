"""
`cirrina` - Opinionated web framework

Implementation of server code.

:license: LGPL, see LICENSE for details
"""

import asyncio
import base64
from functools import wraps
import json

from cryptography import fernet
from aiohttp import web, WSMsgType
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_jrpc import Service, JError, JResponse, decode
from validictory import validate, ValidationError, SchemaError

def rpc_valid(schema=None):
    """
    Validation data by specific validictory configuration.
    """
    def decorator(func):  # pylint: disable=missing-docstring
        @wraps(func)
        def d_func(self, ctx, session, data, *a, **kw):
            """
            Decorator for schema validation.
            """
            try:
                validate(data['params'], schema)
            except ValidationError as err:
                raise InvalidParams(err)
            except SchemaError as err:
                raise InternalError(err)
            return func(self, ctx, session, data['params'], *a, **kw)
        return d_func
    return decorator

class Server:
    """
    cirrina Server implementation.
    """

    login_html = '''<!DOCTYPE HTML>
<html>
  <body>
    <form method="post" action="/login">
      User name:<br/>
        <input type="text" name="username"><br/>
      User password:<br/>
        <input type="password" name="password"><br/>
        <input type="hidden" name="path" value="{0}">
        <input type="submit" value="Login"><br/>
    </form>
  </body>
</html>
'''

    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.app = web.Application(loop=self.loop) #, middlewares=[session_middleware])
        self.srv = None

        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        setup(self.app, EncryptedCookieStorage(secret_key))
        self.GET ("/login", self._login)
        self.POST("/login", self._auth)
        self.login_html = Server.login_html
        self.authenticate = self.dummy_auth
        self.websockets = []

    @staticmethod
    def authenticated(func):
        """
        Decorator to enforce valid session before
        executing the decorated function.
        """
        async def _wrapper(self, request):  # pylint: disable=missing-docstring
            session = await get_session(request)
            if session.new:
                response = web.Response(status=302)
                response.headers['Location'] = '/login?path='+request.path_qs
                return response
            return await func(self, request, session)
        return _wrapper

    async def _start(self):
        """
        Start cirrina server.
        """
        self.srv = await self.loop.create_server(self.app.make_handler(), self.address, self.port)

    async def _login(self, request):
        resp = web.Response(text=self.login_html.format(request.GET.get('path', "/")),
                            content_type="text/html")
        return resp

    async def dummy_auth(self, username, password):
        if username == 'test' and password == 'test':
            return True
        return False

    async def _auth(self, request):
        session = await get_session(request)
        await request.post()
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            if await self.authenticate(username, password):
                print("User authenticated:", username)
                session['username'] = username
                response = web.Response(status=302)
                response.headers['Location'] = request.POST.get('path', "/")
                return response

        print("User authentication failed:", 'username')
        response = web.Response(status=302)
        response.headers['Location'] = '/login'
        session.invalidate()
        return response

    async def _ws_handler(self, request):
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)

        session = await get_session(request)
        if session.new:
            print("websocket: not logged in")
            websocket.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
            websocket.close()
            return websocket

        self.websockets.append(websocket)
        self.websocket_connected(websocket, session)

        async for msg in websocket:
            print("websocket got:", msg)
            if msg.type == WSMsgType.TEXT:
                self.websocket_message(websocket, session, msg.data)
            elif msg.type == WSMsgType.ERROR:
                print('websocket closed with exception %s' %
                  websocket.exception())

        self.websockets.remove(websocket)
        self.websocket_closed(session)

        return websocket

    def websocket_broadcast(self, msg):
        """
        Broadcast the given message to all websocket connections.
        """
        for websocket in self.websockets:
            websocket.send_str(msg)

    def _rpc_handler(self):
        class MyRPC(object):
            cirrina = self

            def __new__(cls, ctx):
                """ Return on call class """
                return cls.__run(cls, ctx)

            @asyncio.coroutine
            def __run(self, ctx):
                """ Run service """
                try:
                    data = yield from decode(ctx)
                except ParseError:
                    return JError().parse()
                except InvalidRequest:
                    return JError().request()
                except InternalError:
                    return JError().internal()

                try:
                    i_app = getattr(MyRPC.cirrina, data['method'])
                    i_app = asyncio.coroutine(i_app)
                except Exception:
                    return JError(data).method()

                session = yield from get_session(ctx)
                try:
                    resp = yield from i_app(ctx, session, data)
                except InvalidParams:
                    return JError(data).params()
                except InternalError:
                    return JError(data).internal()

                return JResponse(jsonrpc={
                    "id": data['id'], "result": resp
                    })

        return MyRPC

    def GET(self, location, handler):
        self.app.router.add_route('GET', location, handler)

    def POST(self, location, handler):
        self.app.router.add_route('POST', location, handler)

    def WS(self):
        self.app.router.add_route('GET', "/ws", self._ws_handler)

    def RPC(self, location):
        self.app.router.add_route('POST', location, self._rpc_handler())

    def STATIC(self, location, path):
        self.app.router.add_static(location, path)

    def run(self):
        """
        Run cirrina server event loop.
        """
        self.loop.run_until_complete(self._start())
        print("Server started at http://%s:%d"%(self.address, self.port))
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        self.loop.close()
        print("done")



