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
import sys
import tempfile
from concurrent import futures
from aiohttp import web, WSMsgType
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_session_file import FileStorage
from aiohttp_swagger import setup_swagger
from collections.abc import Callable
from cryptography import fernet
from functools import wraps, partial
from enum import Enum
from typing import Union


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


class Server(web.Application):
    """
    cirrina Server implementation.
    """

    DEFAULT_STATIC_PATH = os.path.join(os.path.dirname(__file__), 'static')

    class SessionType(Enum):
        ENCRYPTED_COOKIE = 1
        FILE = 2

    def __init__(
            self,  # loop=None,
            login_url="/api/login", logout_url="/api/logout",
            app_kws={},
            session_type=SessionType.ENCRYPTED_COOKIE,
            session_dir=tempfile.mkdtemp(prefix='cirrina-session-'),
            session_max_age=1800):  # 30mins (only for file sessions)
        super().__init__(**app_kws)
        self.login_url = login_url
        self.logout_url = logout_url
        self.session_type = session_type
        self.session_dir = session_dir

        if app_kws is None:
            app_kws = {}

        # executor for threaded http requests
        self.executor = futures.ThreadPoolExecutor()

        #: Holds the asyncio server instance.
        self.srv = None

        #: Holds all websocket handler information.
        self.websockets = {}

        #: Holds all tcp websocket proxy handler information.
        self.tcpsockets = {}

        #: Holds all registered RPC methods.
        self.rpc_methods = {}

        # setup session
        self.encrypted_cookie_session = None
        if self.session_type == Server.SessionType.ENCRYPTED_COOKIE:
            fernet_key = fernet.Fernet.generate_key()
            secret_key = base64.urlsafe_b64decode(fernet_key)
            self.encrypted_cookie_session = EncryptedCookieStorage(secret_key)
            setup(self, self.encrypted_cookie_session)
        elif self.session_type == Server.SessionType.FILE:
            setup(self, FileStorage(session_dir, max_age=session_max_age))

        #: Holds authentication functions
        self.auth_handlers = []
        #: Holds functions which are called upon logout
        self.logout_handlers = []
        #: Holds functions which are called on startup
        self.startup_handlers = []
        #: Holds functions which are called on shutdown
        self.shutdown_handlers = []
        #: Holds handler for unauthorized calls
        self.auth_unauthorized_handler = None

        self.create_context_func = None
        self.destroy_context_func = None

        # add default routes to request handler.
        self.http_post(self.login_url)(self._login)
        self.http_post(self.logout_url)(self._logout)

        self.logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
        self.access_log_class = web.AccessLogger

        # swagger documentation
        self.title = "Cirrina based web application"
        self.description = """Cirrina is a web application framework using aiohttp.
                              See https://github.com/neolynx/cirrina."""
        self.api_version = "0.1"
        self.contact = "André Roth <neolynx@gmail.com>"

        self.waiter_event = asyncio.Event()

        # setup API documentation
        setup_swagger(self,
                      description=self.description,
                      title=self.title,
                      api_version=self.api_version,
                      contact=self.contact)


    def set_context_functions(self, create_context_func, destroy_context_func=None):
        self.create_context_func = create_context_func
        self.destroy_context_func = destroy_context_func

    async def _start(self, address, port):
        """
        Start cirrina server.

        This method starts the asyncio loop server which uses
        the aiohttp web application.:
        """

        for handler in self.startup_handlers:
            try:
                handler()
            except Exception as exc:
                self.logger.exception(exc)

        loop = asyncio.get_event_loop()
        self.srv = await loop.create_server(
            self.make_handler(
                access_log_format='%r %s',
                access_log=self.logger,
                access_log_class=self.access_log_class,
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

        await self.close_websocket_connections()
        await self.shutdown()
        await self.cleanup()

    async def _waiter(self):
        await self.waiter_event.wait()

    def stop(self):
        self.waiter_event.set()

    def run(self, address='127.0.0.1', port=2100, logger=None, debug=False, access_log_class=None):
        """
        Run cirrina server event loop.
        """
        if logger:
            self.logger = logger
        if access_log_class:
            self.access_log_class = access_log_class

        # set cirrina logger loglevel
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._start(address, port))
        self.logger.info("Server started at http://%s:%d", address, port)

        try:
            loop.run_until_complete(self._waiter())
        except KeyboardInterrupt:
            pass

        # running shutdown handlers
        loop.run_until_complete(self._stop())

        self.logger.debug('Stopped cirrina server')

    def _get_asyncio_tasks(self):
        tasks = []
        try:
            if (sys.version_info.major, sys.version_info.minor) < (3, 7):
                # Deprecated in 3.7
                tasks = asyncio.Task.all_tasks()
            tasks = asyncio.all_tasks()
        except RuntimeError:
            pass
        return tasks

    def startup_handler(self, func):
        """
        Decorator to provide one or more startup
        handlers.
        """
        self.startup_handlers.append(func)
        return func

    def shutdown_handler(self, func):
        """
        Decorator to provide one or more shutdown
        handlers.
        """
        self.shutdown_handlers.append(func)
        return func

    # Authentication

    def auth_handler(self, func):
        """
        Decorator to provide one or more authentication
        handlers.
        """
        self.auth_handlers.append(func)
        return func

    def auth_unauthorized(self, func):
        """
        Decorator to provide handler for unauthorized calls.
        """
        self.auth_unauthorized_handler = func
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
            "200":
                description: successful login.
            "400":
                description: login failed
        """
        try:
            params = await request.json()
            username = params.get('username')
            password = params.get('password')
        except Exception as exc:
            self.logger.exception(exc)
            return web.Response(status=400)

        if username and password:
            username = username.lower()
            for auth_handler in self.auth_handlers:
                if (await auth_handler(request, username, password)) is True:
                    self.logger.debug('User authenticated: %s', username)
                    request.cirrina.web_session['username'] = username
                    response = web.Response(status=200)
                    return response
        self.logger.warning('User authentication failed for \'%s\'', str(username))
        await asyncio.sleep(4)
        response = web.Response(status=400)
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
            self.logger.warning('No valid session in request for logout')
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
        async def _wrapper(request, *args, **kwargs):
            if request.cirrina.web_session.new:
                # create new session
                username = None
                password = None
                try:
                    params = await request.json()
                    username = params.get('username')
                    username = username.lower()
                    password = params.get('password')
                except Exception:
                    pass

                # authenticate new session
                authorized = False
                for auth_handler in self.auth_handlers:
                    if (await auth_handler(request, username, password)) is True:
                        authorized = True
                        break
                if not authorized:
                    if self.auth_unauthorized_handler:
                        return await self.auth_unauthorized_handler(request)
                    return web.Response(status=401)
            return await func(request, *args, **kwargs)
        return _wrapper

    def invalidate_sessions(self):
        if self.session_type == Server.SessionType.FILE:
            def walkerror(e):
                raise(e)
            for root, dirs, files in os.walk(self.session_dir, onerror=walkerror):
                for f in files:
                    os.unlink(os.path.join(root, f))
        else:
            # reset secret key
            fernet_key = fernet.Fernet.generate_key()
            self.encrypted_cookie_session._fernet = fernet.Fernet(fernet_key)

    async def close_websocket_connections(self):
        for ws_group in self.websockets:
            for ws in self.websockets[ws_group]["connections"]:
                await ws.close()

    # HTTP protocol

    def _session_wrapper(self, func, threaded=False):
        @wraps(func)
        async def _wrap(request):
            session = await get_session(request)
            request.cirrina = CirrinaContext(web_session=session)
            if self.create_context_func:
                # Errors raised here will result in a generic 500 error
                self.create_context_func(request.cirrina)

            # backward compatibility to older aiohttp API
            if not hasattr(request, "GET") and hasattr(request, "query"):
                request.GET = request.query

            try:
                if threaded:
                    def blocking_wrapper():
                        # run in new loop
                        return asyncio.new_event_loop().run_until_complete(func(request))

                    return await self.loop.run_in_executor(self.executor, blocking_wrapper)
                return await func(request)

            finally:
                if self.destroy_context_func:
                    # Errors raised here will result in a generic 500 error
                    self.destroy_context_func(request.cirrina)

        return _wrap

    def http_static(self, location, path):
        """
        Register new route to static path.
        """
        self.router.add_static(location, path)

    def http_get(self, location, threaded=False):
        """
        Register HTTP GET route.
        """
        self.logger.info(f"adding GET {location}")
        def _wrapper(func):
            self.router.add_route('GET', location, self._session_wrapper(func, threaded))
            return func
        return _wrapper

    def http_head(self, location, threaded=False):
        """
        Register HTTP HEAD route.
        """
        def _wrapper(func):
            self.router.add_route('HEAD', location, self._session_wrapper(func, threaded))
            return func
        return _wrapper

    def http_options(self, location, threaded=False):
        """
        Register HTTP OPTIONS route.
        """
        def _wrapper(func):
            self.router.add_route('OPTIONS', location, self._session_wrapper(func, threaded))
            return func
        return _wrapper

    def http_post(self, location, threaded=False):
        """
        Register HTTP POST route.
        """
        def _wrapper(func):
            self.router.add_route('POST', location, self._session_wrapper(func, threaded))
            return func
        return _wrapper

    def http_put(self, location, threaded=False):
        """
        Register HTTP PUT route.
        """
        def _wrapper(func):
            self.router.add_route('PUT', location, self._session_wrapper(func, threaded))
            return func
        return _wrapper

    def http_patch(self, location, threaded=False):
        """
        Register HTTP PATCH route.
        """
        def _wrapper(func):
            self.router.add_route('PATCH', location, self._session_wrapper(func, threaded))
            return func
        return _wrapper

    def http_delete(self, location, threaded=False):
        """
        Register HTTP DELETE route.
        """
        def _wrapper(func):
            self.router.add_route('DELETE', location, self._session_wrapper(func, threaded))
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

                    self.logger.debug("http_upload: receiving file: '%s'", filename)
                    size = 0
                    # ensure dir exists
                    tmpfile = None
                    with tempfile.NamedTemporaryFile(dir=upload_dir, prefix=filename + ".", delete=False) as f:
                        tmpfile = f.name
                        while True:
                            chunk = await part.read_chunk()  # 8192 bytes by default.
                            if not chunk:
                                break
                            size += len(chunk)
                            f.write(chunk)
                    return await func(request, tmpfile, filename, size)
                self.logger.error("http_upload: multipart field '%s' not found", field)

            self.router.add_route('POST', location, self._session_wrapper(upload_handler))
            return upload_handler
        return _wrapper

    # WebSocket protocol

    async def websocket_broadcast(self, msg, group="main"):
        """
        Broadcast a message to all websocket connections.
        """
        if group not in self.websockets:
            raise Exception("Websocket group '%s' not found" % group)

        if "connections" not in self.websockets[group]:
            raise Exception("Websocket group '%s' has no connections" % group)

        for ws in self.websockets[group]["connections"]:
            try:
                if asyncio.iscoroutinefunction(ws.send_str):
                    await ws.send_str(json.dumps(msg))
                else:
                    ws.send_str(json.dumps(msg))
            except Exception as exc:
                self.websockets[group]["connections"].remove(ws)
                self.logger.exception(exc)

    def websocket_message(self, location, group="main", authenticated=True):
        """
        Decorator for websocket message events.
        """
        async def _ws_wrapper(request):
            return await self._ws_handler(request, group)

        def _wrapper(func):
            self.router.add_route('GET', location, _ws_wrapper)
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

                if asyncio.iscoroutinefunction(ws_client.send_str):
                    await ws_client.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
                else:
                    ws_client.send_str(json.dumps({'status': 401, 'text': "Unauthorized"}))
                await ws_client.close()
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
                    self.logger.debug('websocket closed')
                    break
                elif msg.type == WSMsgType.CLOSING:
                    self.logger.debug('websocket closing')
                    break
                elif msg.type == WSMsgType.TEXT:
                    await self.websockets[group]["handler"](ws_client, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error('websocket closed with exception %s', ws_client.exception())
            except futures._base.CancelledError:
                pass
            except Exception as exc:
                self.logger.exception(exc)

        self.websockets[group]["connections"].remove(ws_client)
        try:
            await self.websockets[group]["disconnect"](ws_client)
        except Exception as exc:
            self.logger.error("websocket: error in disconnect event handler")
            self.logger.exception(exc)

        return ws_client

    # websocket tcp proxy

    def tcp_proxy_setup(self, location, group="main", authenticated: Union[Callable[[web.Request], bool],bool]=True, host="127.0.0.1", port=5900):
        """
        Decorator for TCP to websocket proxy setup
        """
        def _wrapper(func):
            async def _wsproxy_wrapper(request) -> web.Response:
                return await self._wsproxy_handler(request, group, func)

            if group not in self.tcpsockets:
                self.tcpsockets[group] = {}

            self.tcpsockets[group]["authenticated"] = authenticated
            self.tcpsockets[group]["host"] = host
            self.tcpsockets[group]["port"] = port
            self.tcpsockets[group]["connections"] = []
            self.router.add_get(location, _wsproxy_wrapper)

        return _wrapper

    async def _wsproxy_handler(self, request, group, setup: Callable[[web.Request], None]) -> web.StreamResponse:
        session = None
        up = True
        queue = asyncio.Queue()
        handlers = {}

        if callable(self.tcpsockets[group]["authenticated"]):
            session = await get_session(request)

            if not self.tcpsockets[group]["authenticated"](request):
                self.logger.error('tcpproxy: not logged in')
                return web.StreamResponse(status=401)
        elif bool(self.tcpsockets[group]["authenticated"]):
            session = await get_session(request)

            if session.new:
                self.logger.error('tcpproxy: not logged in')
                return web.StreamResponse(status=401)

        if setup is not None:
            await setup(request)

        ws_client = web.WebSocketResponse(protocols=['binary', 'base64'])
        await ws_client.prepare(request)

        ws_client.cirrina = CirrinaWSContext(request, session)

        self.tcpsockets[group]["connections"].append(ws_client)

        async def worker():
            nonlocal up
            while up:
                data = await queue.get()
                try:
                    await ws_client.send_bytes(data)
                except Exception:
                    self.logger.error("tcpproxy: error sending to websocket")
                    await ws_client.close()
                    up = False

        asyncio.ensure_future(worker())

        class TCPProxyProtocol(asyncio.Protocol):
            def __init__(self, cirrina, host, port, client):
                self.cirrina = cirrina
                self.host = host
                self.port = port
                self.client = client

            def connection_made(self, transport):
                self.cirrina.logger.info(f"websocket proxy to {self.host}:{self.port} connected")

                for f in self.cirrina.tcpsockets[group].get("connect", []):
                    f(self.client)


            def data_received(self, data):
                self.cirrina.loop.call_soon_threadsafe(queue.put_nowait, (data))

            def connection_lost(self, exc):
                self.cirrina.logger.debug(f"websocket proxy connection to {self.host}:{self.port} closed")

                for f in self.cirrina.tcpsockets[group].get("disconnect", []):
                    f(self.client)

        host = self.tcpsockets[group]["host"]
        port = self.tcpsockets[group]["port"]
        transport, protocol = await self.loop.create_connection(lambda: TCPProxyProtocol(self, host, port, ws_client), host, port)

        while up:
            try:
                msg = await ws_client.receive()
                if msg.type == WSMsgType.CLOSE or msg.type == WSMsgType.CLOSED:
                    self.logger.debug('websocket proxy connection to websocket closed')
                    up = False
                    break
                elif msg.type == WSMsgType.CLOSING:
                    self.logger.debug('websocket proxy connection to websocket closing')
                    up = False
                    break
                elif msg.type == WSMsgType.BINARY:
                    try:
                        transport.write(msg.data)
                    except Exception:
                        self.logger.error("tcpproxy: error sending to tcp connection")
                        up = False
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error('tcpproxy closed with exception %s', ws_client.exception())
            except futures._base.CancelledError:
                pass
            except Exception as exc:
                self.logger.exception(exc)

        await ws_client.close()
        transport.close()
        self.tcpsockets[group]["connections"].remove(ws_client)

        self.logger.info(f"websocket proxy to {host}:{port} closed")
        return ws_client

    async def close_tcp_proxy_connections(self, group="main", isMatching = lambda r: True):
        connections = self.tcpsockets.get(group, {}).get("connections", [])[:]
        for c in connections:
            if isMatching(c.cirrina.request):
                await c.close()

    def tcp_proxy_connect(self, group="main"):
        """
        Decorator for TCP to websocket proxy connect events.
        """
        if isinstance(group, Callable):
            raise Exception("Decorator needs paranthesis: tcp_proxy_connect()")

        def _decorator(func):
            self.tcpsockets.setdefault(group, {}).setdefault("connect", []).append(func)

        return _decorator

    def tcp_proxy_disconnect(self, group="main"):
        """
        Decorator for TCP to websocket proxy disconnect events.
        """
        if isinstance(group, Callable):
            raise Exception("Decorator needs paranthesis: tcp_proxy_disconnect()")

        def _decorator(func):
            self.tcpsockets.setdefault(group, {}).setdefault("disconnect", []).append(func)

        return _decorator
