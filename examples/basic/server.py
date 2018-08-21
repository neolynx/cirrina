"""
`cirrina` - Opinionated web framework

Simple cirrina server example.

:license: LGPL, see LICENSE for details
"""

import logging
import asyncio

from aiohttp import web

import cirrina

#: Holds the login html template
LOGIN_HTML = '''<!DOCTYPE HTML>
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


#: Holds the logger for the current example
logger = logging.getLogger(__name__)

#: Create cirrina app.
app = cirrina.Server()
app.http_static("/static", cirrina.Server.DEFAULT_STATIC_PATH)
wspath = '/ws'
app.enable_websockets(wspath)
app.enable_rpc('/jrpc')

@app.auth_handler
async def auth_handler(username, password):
    if username == 'admin' and password == 'admin':
        return True
    return False

@app.websocket_connect
async def websocket_connected(ws, session):
    logger.info("websocket: new authenticated connection, user: %s", session['username'])


@app.websocket_message
async def websocket_message(ws, session, msg):
    logger.info("websocket: got message: %s", msg)
    app.websocket_broadcast(msg)


@app.websocket_disconnect
async def websocket_closed(session):
    logger.info('websocket connection closed')


@app.http_get('/login')
async def _login(request, session):
    """
    Send login page to client.
    """
    return web.Response(text=LOGIN_HTML.format(request.get('path', "/")), content_type="text/html")

@app.http_get('/')
@app.authenticated
async def default(request, session):
    """
    ---
    description: This is the default page
    tags:
    - Defaulty Default
    produces:
    - text/html
    responses:
        "200":
            description: successful operation.
        "405":
            description: invalid HTTP Method
    """

    visit_count = session['visit_count'] if 'visit_count' in session else 1
    session['visit_count'] = visit_count + 1

    html = '''<!DOCTYPE HTML>
<html>
<head>
<script type="text/javascript" src="static/cirrina.js"></script>
<script type="text/javascript">
  function log( msg )
  {
    document.body.innerHTML += msg + "<br/>";
    /*alert( msg );*/
  }
  var cirrina = new Cirrina('%s');

  cirrina.onopen = function(ws)
  {
    log("connected" );
    msg = "Hello"
    log("send: " + msg );
    ws.send( msg );
  };
  cirrina.onmessage = function (ws, msg)
  {
    log("got: " + msg );
  };
  cirrina.onclose = function()
  {
    log("disconnected");
  };
</script>
</head>
<body>
 <input type="text" id="text">
 <input type='button' value='Send' onclick="cirrina.send(document.getElementById('text').value);">
 visit count: %d <br/>
</body>
</html>
'''%(wspath, visit_count)
    resp = web.Response(text=html, content_type="text/html")
    return resp


@app.jrpc
async def hello(request, session, msg, n, debug=False):
    logger.info("jrpc hello called: %s - %d, debug: %d", msg, n, debug)
    visit_count = session['visit_count'] if 'visit_count' in session else 1
    session['visit_count'] = visit_count + 1
    app.websocket_broadcast(msg)
    return {"status": msg, 'visit_count': visit_count - 1}


@app.startup
def onstart():
    logger.info("starting up...")


@app.shutdown
def onstop():
    logger.info("shutting down...")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    app.run('0.0.0.0', 8080, debug=True)
