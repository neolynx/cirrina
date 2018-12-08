"""
`cirrina` - Opinionated web framework

Implementation of server code.

:license: LGPL, see LICENSE for details
"""

import asyncio
import base64
import json
import logging
import os
from aiohttp import web, WSMsgType
from aiohttp_session import setup, get_session  # , session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_jrpc import JError, JResponse, decode, InternalError, ParseError
from aiohttp_swagger import setup_swagger
from collections import Callable
from cryptography import fernet
from functools import wraps
from tempfile import NamedTemporaryFile


class CirrinaContext:

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def add_context(self, key, value):
        setattr(self, key, value)


class CirrinaWSContext():
    def __init__(self, request, session):
        self.request = request
        self.web_session = session


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
        self.app = web.Application(loop=self.loop)  #, middlewares=[session_middleware])

        #: Holds the asyncio server instance.
        self.srv = None

        #: Holds all websocket handler information.
        self.websockets = {}

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

    def set_context_functions(self, create_context_func, destroy_context_func=None):
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
        for ws_group in self.websockets:
            for ws in self.websockets[ws_group]:
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
            if (await auth_handler(request, username, password)) is True:
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


    # HTTP protocol

    def _session_wrapper(self, func):
        @wraps(func)
        async def _wrap(request):
            session = await get_session(request)
            request.cirrina = CirrinaContext(web_session=session)
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
                        if received_field == "\"%s\"" % field:
                            filename = received_filename.replace("\"", "")

                    elif getattr(part, field) == "file":
                        filename = part.filename

                    if not filename:
                        continue

                    filename = filename.replace("/", "")  # no paths separators allowed

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


    # WebSocket protocol

    def websocket_broadcast(self, msg, group="main"):
        """
        Broadcast a message to all websocket connections.
        """
        if group not in self.websockets:
            raise Exception("Websocket group '%s' not found" % group)

        if "connections" not in self.websockets[group]:
            raise Exception("Websocket group '%s' has no connections" % group)

        for ws in self.websockets[group]["connections"]:
            # FIXME: use array ?
            ws.send_str('{"status": 200, "message": %s}' % json.dumps(msg))

    def websocket_message(self, location, group="main", authenticated=True):
        """
        Decorator for websocket message events.
        """
        def _ws_wrapper(request):
            return self._ws_handler(request, group)

        def _wrapper(func):
            self.app.router.add_route('GET', location, _ws_wrapper)
            if group not in self.websockets:
                self.websockets[group] = {}
            if "handler" in self.websockets[group]:
                raise Exception("Websocket message handler already defined in group '%s'" % group)
            self.websockets[group]["handler"] = func
            self.websockets[group]["authenticated"] = authenticated
            self.websockets[group]["connections"] = []
            return func
        return _wrapper

    def websocket_connect(self, group="main"):
        """
        Decorator for websocket connect events.
        """
        if isinstance(group, Callable):
            raise Exception("Websocket connect decorator needs paranthesis: websocket_connect()")

        if group not in self.websockets:
            self.websockets[group] = {}
        if "connect" in self.websockets[group]:
            raise Exception("Websocket connect handler already defined in group '%s'" % group)

        def _decorator(func):
            self.websockets[group]["connect"] = func

            @wraps(func)
            def _wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return _wrapper
        return _decorator

    def websocket_disconnect(self, group="main"):
        """
        Decorator for websocket disconnect events.
        """
        if isinstance(group, Callable):
            raise Exception("Websocket disconnect decorator needs paranthesis: websocket_disconnect()")

        if group not in self.websockets:
            self.websockets[group] = {}
        if "disconnect" in self.websockets[group]:
            raise Exception("Websocket disconnect handler already defined in group '%s'" % group)

        def _decorator(func):
            self.websockets[group]["disconnect"] = func

            @wraps(func)
            def _wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return _wrapper
        return _decorator

    async def _ws_handler(self, request, group):
        """
        Handle websocket connections.

        This includes:
            * new connections
            * closed connections
            * messages
        """
        ws_client = web.WebSocketResponse()
        await ws_client.prepare(request)

        session = None
        if self.websockets[group]["authenticated"]:
            session = await get_session(request)
            if session.new:
                self.logger.debug('websocket: not logged in')
                ws_client.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
                ws_client.close()
                return ws_client

        ws_client.cirrina = CirrinaWSContext(request, session)
        self.websockets[group]["connections"].append(ws_client)
        try:
            await self.websockets[group]["connect"](ws_client)
        except Exception as exc:
            self.logger.error("websocket: error in connect event handler")
            self.logger.exception(exc)

        while True:
            try:
                msg = await ws_client.receive()
                if msg.type == WSMsgType.CLOSE or msg.type == WSMsgType.CLOSED:
                    self.logger.info('websocket closed')
                    break

                self.logger.debug("websocket got: %s", msg)
                if msg.type == WSMsgType.TEXT:
                    await self.websockets[group]["handler"](ws_client, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    self.logger.info('websocket closed with exception %s', ws_client.exception())
            except Exception as exc:
                self.logger.exception(exc)

        self.websockets[group]["connections"].remove(ws_client)
        try:
            await self.websockets[group]["disconnect"](ws_client)
        except Exception as exc:
            self.logger.error("websocket: error in disconnect event handler")
            self.logger.exception(exc)

        return ws_client

    # JRPC protocol

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
