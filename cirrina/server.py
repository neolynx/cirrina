"""
`cirrina` - Opinionated web framework

Implementation of server code.

:license: LGPL, see LICENSE for details
"""

import asyncio
import base64
from functools import wraps
import json
import logging
import os

from cryptography import fernet
from aiohttp import web, WSMsgType
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_jrpc import Service, JError, JResponse, decode
from validictory import validate, ValidationError, SchemaError
from aiohttp._ws_impl import WSMsgType


#: Holds the cirrina logger instance
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


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

    DEFAULT_STATIC_PATH = os.path.join(os.path.dirname(__file__), 'static')

    def __init__(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        #: Holds the asyncio event loop which is used to handle requests.
        self.loop = loop

        #: Holds the aiohttp web application instance.
        self.app = web.Application(loop=self.loop) #, middlewares=[session_middleware])

        #: Holds the asyncio server instance.
        self.srv = None

        #: Holds all websocket connections.
        self.websockets = []

        #: Holds all the websocket callbacks.
        self.on_ws_connect = []
        self.on_ws_message = []
        self.on_ws_disconnect = []

        #: Holds all registered RPC methods.
        self.rpc_methods = {}

        # setup cookie encryption for user sessions.
        fernet_key = fernet.Fernet.generate_key()
        secret_key = base64.urlsafe_b64decode(fernet_key)
        setup(self.app, EncryptedCookieStorage(secret_key))

        #: Holds the method for user authentication.
        #  This can be any method accepting username and password
        #  and returning a bool.
        self.authenticate = self.dummy_auth

        # add default routes to request handler.
        self.post('/login')(self._auth)

    @asyncio.coroutine
    def _start(self, address, port):
        """
        Start cirrina server.

        This method starts the asyncio loop server which uses
        the aiohttp web application.:
        """
        self.srv = yield from self.loop.create_server(self.app.make_handler(), address, port)

    def authenticated(self, func):
        """
        Decorator to enforce valid session before
        executing the decorated function.
        """
        @asyncio.coroutine
        def _wrapper(request):  # pylint: disable=missing-docstring
            session = yield from get_session(request)
            if session.new:
                response = web.Response(status=302)
                response.headers['Location'] = '/login?path='+request.path_qs
                return response
            return (yield from func(request, session))
        return _wrapper

    @asyncio.coroutine
    def dummy_auth(self, username, password):
        """
        Dummy authentication implementation for testing purposes.

        This method should be removed.
        """
        if username == 'test' and password == 'test':
            return True
        return False

    @asyncio.coroutine
    def _auth(self, request):
        """
        Authenticate the user with the given request data.

        Username and Password a received with the HTTP POST data
        and the ``username`` and ``password`` fields.
        On success a new session will be created.
        """
        session = yield from get_session(request)

        # get username and password from POST request
        yield from request.post()
        username = request.POST.get('username')
        password = request.POST.get('password')

        # check if username and password are valid
        if not (yield from self.authenticate(username, password)):
            logger.debug('User authentication failed: %s', username)
            response = web.Response(status=302)
            response.headers['Location'] = '/login'
            session.invalidate()
            return response

        logger.debug('User authenticated: %s', username)
        session['username'] = username
        response = web.Response(status=302)
        response.headers['Location'] = request.POST.get('path', '/')
        return response

    @asyncio.coroutine
    def _ws_handler(self, request):
        """
        Handle websocket connections.

        This includes:
            * new connections
            * closed connections
            * messages
        """
        websocket = web.WebSocketResponse()
        yield from websocket.prepare(request)

        session = yield from get_session(request)
        if session.new:
            logger.debug('websocket: not logged in')
            websocket.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
            websocket.close()
            return websocket

        self.websockets.append(websocket)
        for func in self.on_ws_connect:
            yield from func(websocket, session)

        while True:
            msg = yield from websocket.receive()
            if msg.type == WSMsgType.CLOSE or msg.type == WSMsgType.CLOSED:
                logger.debug('websocket closed')
                break

            logger.debug("websocket got: %s", msg)
            if msg.type == WSMsgType.TEXT:
                for func in self.on_ws_message:
                    yield from func(websocket, session, msg.data)
            elif msg.type == WSMsgType.ERROR:
                logger.debug('websocket closed with exception %s', websocket.exception())

            asyncio.sleep(0.1)

        self.websockets.remove(websocket)
        for func in self.on_ws_disconnect:
            yield from func(session)

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
                    i_app = MyRPC.cirrina.rpc_methods[data['method']]
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

    def get(self, location):
        """
        Register new HTTP GET route.
        """
        def _wrapper(func):
            self.app.router.add_route('GET', location, func)
            return func
        return _wrapper

    def post(self, location):
        """
        Register new HTTP POST route.
        """
        def _wrapper(func):
            self.app.router.add_route('POST', location, func)
            return func
        return _wrapper

    def enable_websockets(self):
        """
        Enable websocket communication.
        """
        self.app.router.add_route('GET', "/ws", self._ws_handler)

    def enable_rpc(self, location):
        """
        Register new JSON RPC method.
        """
        self.app.router.add_route('POST', location, self._rpc_handler())

    def register_rpc(self, func):
        """
        Register RPC method
        """
        self.rpc_methods[func.__name__] = func
        return func

    def static(self, location, path):
        """
        Register new route to static path.
        """
        self.app.router.add_static(location, path)

    def websocket_connect(self, func):
        """
        Add callback for websocket connect event.
        """
        self.on_ws_connect.append(func)
        return func

    def websocket_message(self, func):
        """
        Add callback for websocket message event.
        """
        self.on_ws_message.append(func)
        return func

    def websocket_disconnect(self, func):
        """
        Add callback for websocket disconnect event.
        """
        self.on_ws_disconnect.append(func)
        return func

    def run(self, address='127.0.0.1', port=2100, debug=False):
        """
        Run cirrina server event loop.
        """
        # set cirrina logger loglevel
        logger.setLevel(logging.DEBUG if debug else logging.INFO)

        self.loop.run_until_complete(self._start(address, port))
        logger.info("Server started at http://%s:%d", address, port)

        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        self.loop.close()

        logger.info('Stopped cirrina server')