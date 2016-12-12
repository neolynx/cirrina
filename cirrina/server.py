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
from aiohttp_jrpc import JError, JResponse, decode, InvalidParams, InternalError
from validictory import validate, ValidationError, SchemaError
from aiohttp._ws_impl import WSMsgType
from aiohttp_swagger import setup_swagger
from functools import wraps

#: Holds the cirrina logger instance
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _session_wrapper(func):
    @wraps(func)
    def _addsess(request):
        session = yield from get_session(request)
        return (yield from func(request, session))
    return _addsess


class Server:
    """
    cirrina Server implementation.
    """

    DEFAULT_STATIC_PATH = os.path.join(os.path.dirname(__file__), 'static')

    def __init__(self, loop=None, login_url="/login", logout_url="/logout"):
        if loop is None:
            loop = asyncio.get_event_loop()
        #: Holds the asyncio event loop which is used to handle requests.
        self.loop = loop

        # remember the login/logout urls
        self.login_url = login_url
        self.logout_url = logout_url

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

        #: Holds authentication functions
        self.auth_handlers = []
        #: Holds functions which are called upon logout
        self.logout_handlers = []
        #: Holds functions which are called on startup
        self.startup_handlers = []
        #: Holds functions which are called on shutdown
        self.shutdown_handlers = []

        # add default routes to request handler.
        self.http_post(self.login_url)(self._login)
        self.http_post(self.logout_url)(self._logout)

        # swagger documentation
        self.title = "Cirrina based web application"
        self.description = """Cirrina is a web application framework using aiohttp.
                              See https://github.com/neolynx/cirrina."""
        self.api_version = "0.1"
        self.contact = "André Roth <neolynx@gmail.com>"


    @asyncio.coroutine
    def _start(self, address, port):
        """
        Start cirrina server.

        This method starts the asyncio loop server which uses
        the aiohttp web application.:
        """

        # setup API documentation
        setup_swagger(self.app,
                      description=self.description,
                      title=self.title,
                      api_version=self.api_version,
                      contact=self.contact)

        for handler in self.startup_handlers:
            handler()

        self.srv = yield from self.loop.create_server(self.app.make_handler(), address, port)

    @asyncio.coroutine
    def _stop(self):
        """
        Stop cirrina server.

        This method stops the asyncio loop server which uses
        the aiohttp web application.:
        """
        logger.debug('Stopping cirrina server...')
        for handler in self.shutdown_handlers:
            handler()
        for ws in self.websockets:
            ws.close()
        self.app.shutdown()

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

        self.loop.run_until_complete(self._stop())
        logger.debug("Closing all tasks...")
        for task in asyncio.Task.all_tasks():
            task.cancel()
        self.loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks()))
        logger.debug("Closing the loop...")
        self.loop.close()

        logger.info('Stopped cirrina server')


    def startup(self, func):
        """
        Decorator to provide one or more startup
        handlers.
        """
        self.startup_handlers.append(func)
        return func


    def shutdown(self, func):
        """
        Decorator to provide one or more shutdown
        handlers.
        """
        self.shutdown_handlers.append(func)
        return func


    ### Authentication ###

    def auth_handler(self, func):
        """
        Decorator to provide one or more authentication
        handlers.
        """
        self.auth_handlers.append(func)
        return func

    def logout_handler(self, func):
        """
        Decorator to specify function which should
        be called upon user logout.
        """
        self.logout_handlers.append(func)
        return func

    @asyncio.coroutine
    def _login(self, request, session):
        """
        Authenticate the user with the given request data.

        Username and Password a received with the HTTP POST data
        and the ``username`` and ``password`` fields.
        On success a new session will be created.

        ---
        description: This is the login handler
        tags:
        - Authentication
        consumes:
        - application/x-www-form-urlencoded
        parameters:
        - name: username
          in: formData
          required: true
          pattern: '[a-z0-9]{8,64}'
          minLength: 8
          maxLength: 64
          type: string
        - name: password
          in: formData
          required: true
          type: string
          format: password
        produces:
        - text/plain
        responses:
            "302":
                description: successful login.
            "405":
                description: invalid HTTP Method
        """

        # get username and password from POST request
        yield from request.post()
        username = request.POST.get('username')
        password = request.POST.get('password')

        # check if username and password are valid
        for auth_handler in self.auth_handlers:
            if (yield from auth_handler(username, password)) == True:
                logger.debug('User authenticated: %s', username)
                session['username'] = username
                response = web.Response(status=302)
                response.headers['Location'] = request.POST.get('path', '/')
                return response
        logger.debug('User authentication failed: %s', username)
        response = web.Response(status=302)
        response.headers['Location'] = self.login_url
        session.invalidate()
        return response

    @asyncio.coroutine
    def _logout(self, request, session):
        """
        Logout the user which is used in this request session.

        If the request is not part of a user session - nothing happens.

        ---
        description: This is the logout handler
        tags:
        - Authentication
        produces:
        - text/plain
        responses:
            "200":
                description: successful logout.
        """

        if not session:
            logger.debug('No valid session in request for logout')
            return web.Response(status=200)  # FIXME: what should be returned?

        # run all logout handlers before invalidating session
        for func in self.logout_handlers:
            func(session)

        logger.debug('Logout user from session')
        session.invalidate()
        return web.Response(status=200)

    def authenticated(self, func):
        """
        Decorator to enforce valid session before
        executing the decorated function.
        """
        @wraps(func)
        @asyncio.coroutine
        def _wrapper(request, session):  # pylint: disable=missing-docstring
            if session.new:
                response = web.Response(status=302)
                response.headers['Location'] = self.login_url + "?path=" + request.path_qs
                return response
            return (yield from func(request, session))
        return _wrapper


    ### HTTP protocol ###

    def http_static(self, location, path):
        """
        Register new route to static path.
        """
        self.app.router.add_static(location, path)


    def http_get(self, location):
        """
        Register HTTP GET route.
        """
        def _wrapper(func):
            self.app.router.add_route('GET', location, _session_wrapper(func))
            return func
        return _wrapper

    def http_head(self, location):
        """
        Register HTTP HEAD route.
        """
        def _wrapper(func):
            self.app.router.add_route('HEAD', location, _session_wrapper(func))
            return func
        return _wrapper

    def http_options(self, location):
        """
        Register HTTP OPTIONS route.
        """
        def _wrapper(func):
            self.app.router.add_route('OPTIONS', location, _session_wrapper(func))
            return func
        return _wrapper

    def http_post(self, location):
        """
        Register HTTP POST route.
        """
        def _wrapper(func):
            self.app.router.add_route('POST', location, _session_wrapper(func))
            return func
        return _wrapper

    def http_put(self, location):
        """
        Register HTTP PUT route.
        """
        def _wrapper(func):
            self.app.router.add_route('PUT', location, _session_wrapper(func))
            return func
        return _wrapper

    def http_patch(self, location):
        """
        Register HTTP PATCH route.
        """
        def _wrapper(func):
            self.app.router.add_route('PATCH', location, _session_wrapper(func))
            return func
        return _wrapper

    def http_delete(self, location):
        """
        Register HTTP DELETE route.
        """
        def _wrapper(func):
            self.app.router.add_route('DELETE', location, _session_wrapper(func))
            return func
        return _wrapper


    ### WebSocket protocol ###

    def enable_websockets(self, location):
        """
        Enable websocket communication.
        """
        self.app.router.add_route('GET', location, self._ws_handler)

    def websocket_broadcast(self, msg):
        """
        Broadcast a message to all websocket connections.
        """
        for websocket in self.websockets:
            # FIXME: use array
            websocket.send_str('{"status": 200, "message": %s}'%json.dumps(msg))

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

            yield from asyncio.sleep(0.1)

        self.websockets.remove(websocket)
        for func in self.on_ws_disconnect:
            yield from func(session)

        return websocket


    ### JRPC protocol ###

    def enable_rpc(self, location):
        """
        Register new JSON RPC method.
        """
        self.app.router.add_route('POST', location, self._rpc_handler())

    def jrpc(self, func):
        """
        Register RPC method
        """
        self.rpc_methods[func.__name__] = func
        return func

    def _rpc_handler(self):
        """
        Handle rpc calls.
        """
        class _rpc(object):
            cirrina = self

            def __new__(cls, request):
                """ Return on call class """
                return cls.__run(cls, request)

            @asyncio.coroutine
            def __run(self, request):
                """ Run service """
                try:
                    data = yield from decode(request)
                except ParseError:
                    return JError().parse()
                except InvalidRequest:
                    return JError().request()
                except InternalError:
                    return JError().internal()

                try:
                    method = _rpc.cirrina.rpc_methods[data['method']]
                except Exception:
                    return JError(data).method()

                session = yield from get_session(request)
                try:
                    resp = yield from method(request, session, *data['params']['args'], **data['params']['kw'])
                except TypeError as e:
                    # workaround for JError.custom bug
                    return JResponse(jsonrpc={
                        'id': data['id'],
                        'error': {'code': -32602, 'message': str(e)},
                    })
                except InternalError:
                    return JError(data).internal()

                return JResponse(jsonrpc={
                    "id": data['id'], "result": resp
                    })

        return _rpc
