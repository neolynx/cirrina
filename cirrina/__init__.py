import asyncio
from aiohttp_jrpc import Service, JError, jrpc_errorhandler_middleware
from aiohttp import web, WSMsgType
from cryptography import fernet
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
import base64
import json

class Server:

    login_html = '''<!DOCTYPE HTML>
<html>
  <body>
    <form method="post" action="/login">
      User name:<br/>
        <input type="text" name="username"><br/>
      User password:<br/>
        <input type="password" name="password"><br/>
        <input type="hidden" name="path" value="%s">
        <input type="submit" value="Login"><br/>
    </form>
  </body>
</html>
'''

    def __init__(self, bind, port):
        self.bind = bind
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.app = web.Application(loop=self.loop) #, middlewares=[session_middleware])

        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        setup(self.app, EncryptedCookieStorage(secret_key))
        self.GET ("/login", self._login)
        self.POST("/login", self._auth)
        self.login_html = Server.login_html
        self.authenticate = self.dummy_auth
        self.websockets = []

    # decorator
    def authenticated(func):
        async def func_wrapper(self, request):
            session = await get_session(request)
            if session.new:
                response = web.Response(status=302)
                response.headers['Location'] = '/login?path='+request.path_qs
                return response
            return await func(self, request, session)
        return func_wrapper

    async def _start(self):
        self.srv = await self.loop.create_server(self.app.make_handler(), self.bind, self.port)

    async def _login(self, request):
        resp = web.Response(text=(self.login_html%(request.GET.get('path', "/"))), content_type="text/html")
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
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        session = await get_session(request)
        if session.new:
            print("websocket: not logged in")
            ws.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
            ws.close()
            return ws

        self.websockets.append(ws)

        self.websocket_connected(ws, session)

        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                self.websocket_message(ws, session, msg.data)
            elif msg.type == WSMsgType.ERROR:
                print('websocket closed with exception %s' %
                  ws.exception())

        self.websockets.remove(ws)
        self.websocket_closed(session)

        return ws

    def GET(self, location, handler):
        self.app.router.add_route('GET', location, handler)

    def POST(self, location, handler):
        self.app.router.add_route('POST', location, handler)

    def WS(self):
        self.app.router.add_route('GET', "/ws", self._ws_handler)

    def RPC(self, location, handler):
        self.app.router.add_route('POST', location, handler)

    def STATIC(self, location, path):
        self.app.router.add_static(location, path)

    def run(self):
        self.loop.run_until_complete(self._start())
        print("Server started at http://127.0.0.1:8080")
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        #self.srv.stop()
        self.loop.close()
        #print("Stopping server")
        #try:
        #except Excetion as e:
            #pass
        print("done")
