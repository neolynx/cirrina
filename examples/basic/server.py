import cirrina
from aiohttp import web
import json
import logging

#: Holds the logger for the current example
logger = logging.getLogger(__name__)


class MyServer(cirrina.Server):

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

    def __init__(self, bind, port):
        cirrina.Server.__init__(self, bind, port)
        self.get('/login', self._login)
        self.get("/", self.default)
        self.rpc("/jrpc")
        self.ws()
        self.static("/static", cirrina.Server.DEFAULT_STATIC_PATH)


    async def _login(self, request):
        """
        Send login page to client.
        """
        return web.Response(text=self.login_html.format(request.GET.get('path', "/")), content_type="text/html")

    ### HTTP

    @cirrina.Server.authenticated
    async def default(self, request, session):
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
      var cirrina = new Cirrina();

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
'''%visit_count
        resp = web.Response(text=html, content_type="text/html")
        return resp


    ### WebSockets

    def websocket_connected(self, ws, session):
        logger.info("websocket: new authenticated connection, user: %s", session['username'])

    def websocket_message(self, ws, session, msg):
        logger.info("websocket: got message: %s", msg)
        self.websocket_broadcast(msg)

    def websocket_closed(self, session):
        logger.info('websocket connection closed')

    ### JSON RPC

    SCH = {
        "type": "object",
        "properties": {
            "data": {"type": "string"},
        },
    }

    @cirrina.rpc_valid(SCH)
    def hello(self, request, session, data):
        logger.info("jrpc hello called: %s", data["data"])
        visit_count = session['visit_count'] if 'visit_count' in session else 1
        session['visit_count'] = visit_count + 1
        self.websocket_broadcast(data["data"])
        return {"status": data["data"], 'visit_count': visit_count - 1}


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    c = MyServer("0.0.0.0", 8080)
    c.run()
