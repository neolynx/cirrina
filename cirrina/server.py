"""
`cirrina` - Opinionated web framework

Implementation of server code.

:license: LGPL, see LICENSE for details

TODO:

    Maybe restructure:
    - WS Management
    - JSONRPC management
    - Sessions and auth management

    What about using an external authentication handling library?
    Pretty sure that should be better covered somewhere.

"""

from functools import wraps
from pathlib import Path
import asyncio
import base64
import logging

from aiohttp import web, WSMsgType
from aiohttp_jrpc import JError, JResponse, decode, InternalError
from aiohttp_jrpc import ParseError, InvalidRequest
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_swagger import setup_swagger
from cryptography.fernet import Fernet

#: Holds the cirrina logger instance
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _session_wrapper(func):
    @wraps(func)
    async def _addsess(request):
        return await func(request, await get_session(request))
    return _addsess


class Server:
    """ Cirrina Server implementation.  """
    # pylint: disable=no-member, too-many-instance-attributes
    DEFAULT_STATIC_PATH = Path(__file__).parent.absolute() / 'static'

    def __init__(self, loop=None, login_url="/login", logout_url="/logout",
                 debug=False):
        #: Holds the asyncio event loop which is used to handle requests.
        self.loop = loop if loop is not None else asyncio.get_event_loop()

        # remember the login/logout urls
        self.urls = {"login": login_url, 'logout': logout_url}

        #: Holds the web application instance.
        self.app = web.Application(loop=self.loop, debug=debug)

        #: Holds all websocket connections.
        self.websockets = []

        #: Holds all the websocket callbacks.
        self.on_ws_connect = []
        self.on_ws_message = []
        self.on_ws_disconnect = []

        #: Holds all registered RPC methods.
        self.rpc_methods = {}

        # setup cookie encryption for user sessions.
        setup(self.app, EncryptedCookieStorage(
            base64.urlsafe_b64decode(Fernet.generate_key())))

        #: Holds authentication functions
        self.auth_handlers = []

        #: Holds functions which are called upon logout
        self.logout_handlers = []

        #: Holds functions which are called on startup
        self.startup_handlers = []

        #: Holds functions which are called on shutdown
        self.shutdown_handlers = []

        # In the end I dont like this solution.
        # But I dont like to repeat the same code over and over again
        # either.
        self.startup = self.handler_register(self.startup_handlers)
        self.shutdown = self.handler_register(self.shutdown_handlers)
        self.auth_handler = self.handler_register(self.auth_handlers)
        self.logout_handler = self.handler_register(self.logout_handlers)
        self.websocket_connect = self.handler_register(self.on_ws_connect)
        self.websocket_message = self.handler_register(self.on_ws_message)
        self.websocket_disconnect = self.handler_register(
            self.on_ws_disconnect)

        self.http_get = self.wrapper('GET')
        self.http_post = self.wrapper('POST')
        self.http_head = self.wrapper('HEAD')
        self.http_put = self.wrapper('PUT')
        self.http_patch = self.wrapper('PATCH')
        self.http_delete = self.wrapper('DELETE')

        # add default routes to request handler.
        self.http_post(self.urls['login'])(self._login)
        self.http_post(self.urls['logout'])(self._logout)

    def handler_register(self, where):
        """ Register handlers wrapper """
        def _register(func):
            where.append(func)
            return func
        return _register

    def wrapper(self, method):
        """ Return a func wrapper for session management """
        def _wrapper1(location):
            def _wrapper(func):
                self.app.router.add_route(
                    method, location, _session_wrapper(func))
                return func
            return _wrapper
        return _wrapper1

    def run(self, address='127.0.0.1', port=2100, swagger_info=None):
        """
        Run cirrina server event loop.
        """
        # setup API documentation
        if swagger_info:
            setup_swagger(self.app, **swagger_info)

        for handler in self.startup_handlers:
            self.app.on_startup.append(handler)

        for handler in self.shutdown_handlers:
            self.app.on_shutdown.append(handler)

        return web.run_app(self.app, host=address, port=port)

    async def _login(self, request, session):
        """ Authenticate the user with the given request data.

        Username and Password a received with the HTTP POST data
        and the ``username`` and ``password`` fields.
        On success a new session will be created.

        ---
        description: Login handler

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
        - text/html

        responses:
            "302":
                description: Login successfull/unsuccessfull
                             (will be redirected)
            "405":
                description: invalid HTTP Method
        """

        # get username and password from POST request
        ldata = await request.post()

        # check if username and password are valid in any of the auth handlers
        for auth in self.auth_handlers:
            if await auth(ldata['username'], ldata['password']):
                session['username'] = ldata["username"]
                raise web.HTTPFound(ldata.get('path', '/'))

        session.invalidate()
        raise web.HTTPFound(self.login_url)

    async def _logout(self, _, session):
        """ Logout the user which is used in this request session.

        If the request is not part of a user session - nothing happens.

        description: Logout handler

        tags:
        - Authentication

        produces:
        - text/plain

        responses:
            "200":
                description: successful logout.
        """

        if not session:
            raise web.HTTPUnauthorized()

        for func in self.logout_handlers:
            await func(session)

        session.invalidate()
        return web.Response(status=200)

    def authenticated(self, func):
        """ Decorator to enforce valid session before
            executing the decorated function.
        """
        @wraps(func)
        async def _wrapper(request, session):
            if session.new:
                raise web.HTTPFound("{}?path={}".format(
                    self.urls['login'], request.path_qa))
            return await func(request, session)
        return _wrapper

    def http_static(self, loc, path):
        """ Http static path """
        return self.app.router.add_static(loc, path)

    # WebSocket protocol
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
            websocket.send_json({"status": 200, "message": msg})

    async def _ws_handler(self, request):
        """
        Handle websocket connections.

        This includes:
            * new connections
            * closed connections
            * messages
        """
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)

        session = await get_session(request)

        # Allow no-auth if we haven't setup any authentication methods.
        if session.new and self.auth_handlers:
            logger.debug('Not logged in websocket attempt')
            websocket.send_json({'status': 401, 'text': "Unauthorized"})
            websocket.close()
            return websocket

        self.websockets.append(websocket)

        for func in self.on_ws_connect:
            await func(websocket, session)

        async for msg in websocket:
            errors = (WSMsgType.ERROR, WSMsgType.CLOSE, WSMsgType.CLOSED)
            if msg.type in errors:
                logger.debug('Websocket closed (%s)', websocket.exception())
                break
            elif msg.type == WSMsgType.TEXT:
                for func in self.on_ws_message:
                    await func(websocket, session, msg)

            await asyncio.sleep(0.1)

        self.websockets.remove(websocket)
        for func in self.on_ws_disconnect:
            await func(session)

        return websocket

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
        async def _run(request):
            """ Return a coroutine upon object initialization """
            try:
                error = None
                data = await decode(request)
            except ParseError:
                error = JError().parse()
            except InvalidRequest:
                error = JError().request()
            except InternalError:
                error = JError().internal()
            finally:
                if error is not None:
                    # pylint: disable=lost-exception
                    return error

            # pylint: disable=bare-except
            try:
                method = self.cirrina.rpc_methods[data['method']]
            except:
                return JError(data).method()

            session = await get_session(request)

            try:
                resp = await method(request, session,
                                    *data['params']['args'],
                                    **data['params']['kw'])
            except TypeError as err:
                # workaround for JError.custom bug
                return JResponse(jsonrpc={
                    'id': data['id'],
                    'error': {'code': -32602, 'message': str(err)}})
            except InternalError:
                return JError(data).internal()

            return JResponse(
                jsonrpc={"id": data['id'], "result": resp})

        _run.self = self
        return _run
