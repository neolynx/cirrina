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
from tempfile import NamedTemporaryFile

from cryptography import fernet
from aiohttp import web, WSMsgType
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_jrpc import JError, JResponse, decode, InvalidParams, InternalError, ParseError
from validictory import validate, ValidationError, SchemaError
from aiohttp import WSMsgType
from aiohttp_swagger import setup_swagger
from functools import wraps


class CirrinaContext:

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def add_context(self, key, value):
        setattr(self, key, value)

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

        self.create_context_func = None
        self.destroy_context_func = None

        # add default routes to request handler.
        self.http_post(self.login_url)(self._login)
        self.http_post(self.logout_url)(self._logout)

        self.logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

        # swagger documentation
        self.title = "Cirrina based web application"
        self.description = """Cirrina is a web application framework using aiohttp.
                              See https://github.com/neolynx/cirrina."""
        self.api_version = "0.1"
        self.contact = "André Roth <neolynx@gmail.com>"

    def set_context_functions(self, create_context_func, destroy_context_func = None):
        self.create_context_func = create_context_func
        self.destroy_context_func = destroy_context_func

    async def _start(self, address, port):
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
            try:
                handler()
            except Exception as exc:
                self.logger.exception(exc)

        self.srv = await self.loop.create_server(
            self.app.make_handler(
                access_log_format='%r %s',
                access_log=self.logger,
                logger=self.logger),
                address,
                port)

    async def _stop(self):
        """
        Stop cirrina server.

        This method stops the asyncio loop server which uses
        the aiohttp web application.:
        """
        self.logger.debug('Stopping cirrina server...')
        for handler in self.shutdown_handlers:
            try:
                handler()
            except Exception as exc:
                self.logger.exception(exc)
        for ws in self.websockets:
            ws.close()
        self.app.shutdown()

    def run(self, address='127.0.0.1', port=2100, logger=None, debug=False):
        """
        Run cirrina server event loop.
        """
        if logger:
            self.logger = logger

        # set cirrina logger loglevel
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)

        self.loop.run_until_complete(self._start(address, port))
        self.logger.info("Server started at http://%s:%d", address, port)

        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass

        self.loop.run_until_complete(self._stop())
        self.logger.debug("Closing all tasks...")
        for task in asyncio.Task.all_tasks():
            task.cancel()
        self.loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks()))
        self.logger.debug("Closing the loop...")
        self.loop.close()

        self.logger.info('Stopped cirrina server')


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

    async def _login(self, request):
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
        data = await request.post()
        username = data.get('username')
        password = data.get('password')

        # check if username and password are valid
        for auth_handler in self.auth_handlers:
            if (await auth_handler(request, username, password)) == True:
                self.logger.debug('User authenticated: %s', username)
                request.cirrina.web_session['username'] = username
                response = web.Response(status=302)
                response.headers['Location'] = data.get('path', '/')
                return response
        self.logger.debug('User authentication failed: %s', username)
        response = web.Response(status=302)
        response.headers['Location'] = self.login_url
        request.cirrina.web_session.invalidate()
        return response

    async def _logout(self, request):
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

        if not request.cirrina.web_session:
            self.logger.debug('No valid session in request for logout')
            return web.Response(status=200)  # FIXME: what should be returned?

        # run all logout handlers before invalidating session
        for func in self.logout_handlers:
            func(request)

        self.logger.debug('Logout user from session')
        request.cirrina.web_session.invalidate()
        return web.Response(status=200)

    def authenticated(self, func):
        """
        Decorator to enforce valid session before
        executing the decorated function.
        """
        @wraps(func)
        async def _wrapper(request):  # pylint: disable=missing-docstring
            if request.cirrina.web_session.new:
                response = web.Response(status=302)
                response.headers['Location'] = self.login_url + "?path=" + request.path_qs
                return response
            return (await func(request))
        return _wrapper


    ### HTTP protocol ###

    def _session_wrapper(self, func):
        @wraps(func)
        async def _wrap(request):
            session = await get_session(request)
            request.cirrina = CirrinaContext(web_session = session)
            if self.create_context_func:
                self.create_context_func(request.cirrina)
            ret = (await func(request))
            if self.destroy_context_func:
                self.destroy_context_func(request.cirrina)
            return ret
        return _wrap

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
            self.app.router.add_route('GET', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_head(self, location):
        """
        Register HTTP HEAD route.
        """
        def _wrapper(func):
            self.app.router.add_route('HEAD', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_options(self, location):
        """
        Register HTTP OPTIONS route.
        """
        def _wrapper(func):
            self.app.router.add_route('OPTIONS', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_post(self, location):
        """
        Register HTTP POST route.
        """
        def _wrapper(func):
            self.app.router.add_route('POST', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_put(self, location):
        """
        Register HTTP PUT route.
        """
        def _wrapper(func):
            self.app.router.add_route('PUT', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_patch(self, location):
        """
        Register HTTP PATCH route.
        """
        def _wrapper(func):
            self.app.router.add_route('PATCH', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_delete(self, location):
        """
        Register HTTP DELETE route.
        """
        def _wrapper(func):
            self.app.router.add_route('DELETE', location, self._session_wrapper(func))
            return func
        return _wrapper

    def http_upload(self, location, field="file", upload_dir="/tmp/cirrina-upload"):
        """
        Register HTTP POST route for file uploads.
        """
        def _wrapper(func):
            async def upload_handler(request):
                reader = await request.multipart()
                async for part in reader:
                    filename = None
                    if not hasattr(part, field):
                        content = part.headers["Content-Disposition"].split("; ")
                        for c in content:
                            p = c.split("=")
                            if len(p) != 2:
                                continue
                            k, v = p
                            if k == "name":
                                received_field = v
                            elif k == "filename":
                                received_filename = v
                        if received_field == "\"%s\""%field:
                            filename = received_filename.replace("\"", "")

                    elif getattr(part, field) == "file":
                        filename = part.filename

                    if not filename:
                        continue

                    filename = filename.replace("/", "") # no paths separators allowed

                    self.logger.info("http_upload: receiving file: '%s'", filename)
                    size = 0
                    # ensure dir exists
                    tempfile = None
                    with NamedTemporaryFile(dir=upload_dir, prefix=filename + ".", delete=False) as f:
                        tempfile = f.name
                        while True:
                            chunk = await part.read_chunk()  # 8192 bytes by default.
                            if not chunk:
                                break
                            size += len(chunk)
                            f.write(chunk)
                    return await func(request, tempfile, filename, size)
                self.logger.error("http_upload: multipart field '%s' not found", field)

            self.app.router.add_route('POST', location, self._session_wrapper(upload_handler))
            return upload_handler
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
        if session.new:
            self.logger.debug('websocket: not logged in')
            websocket.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
            websocket.close()
            return websocket

        self.websockets.append(websocket)
        for func in self.on_ws_connect:
            await func(websocket, session)

        while True:
            try:
                msg = await websocket.receive()
                if msg.type == WSMsgType.CLOSE or msg.type == WSMsgType.CLOSED:
                    self.logger.info('websocket closed')
                    break

                self.logger.debug("websocket got: %s", msg)
                if msg.type == WSMsgType.TEXT:
                    for func in self.on_ws_message:
                        await func(websocket, session, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    self.logger.info('websocket closed with exception %s', websocket.exception())
            except Exception as exc:
                self.logger.exception(exc)

        self.websockets.remove(websocket)
        for func in self.on_ws_disconnect:
            await func(session)

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

            async def __run(self, request):
                """ Run service """
                _rpc.cirrina.logger.debug("RPC call")
                try:
                    data = await decode(request)
                except ParseError:
                    _rpc.cirrina.logger.error('JRPC parse error')
                    return JError().parse()
                except InvalidRequest:
                    _rpc.cirrina.logger.error('JRPC invalid request')
                    return JError().request()
                except InternalError:
                    _rpc.cirrina.logger.error('JRPC internal error')
                    return JError().internal()

                try:
                    method = _rpc.cirrina.rpc_methods[data['method']]
                except Exception:
                    _rpc.cirrina.logger.error("JRPC method not found: '%s'"%data['method'])
                    return JError(data).method()

                session = await get_session(request)
                try:
                    resp = await method(request, session, *data['params']['args'], **data['params']['kw'])
                except TypeError as e:
                    # workaround for JError.custom bug
                    _rpc.cirrina.logger.error('JRPC argument type error')
                    return JResponse(jsonrpc={
                        'id': data['id'],
                        'error': {'code': -32602, 'message': str(e)},
                    })
                except InternalError:
                    _rpc.cirrina.logger.error('JRPC internal error')
                    return JError(data).internal()

                return JResponse(jsonrpc={
                    "id": data['id'], "result": resp
                    })

        return _rpc
