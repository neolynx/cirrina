#!/usr/bin/python3

import cirrina
from aiohttp import web, WSMsgType
from aiohttp_session import get_session
from aiohttp_jrpc import Service, JError, jrpc_errorhandler_middleware
import json

### HTTP

@cirrina.Server.authenticated
async def default(request, session):
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
     <input type='button' value='Send' onclick="cirrina.send('glu');">
     visit count: %d <br/>
   </body>
</html>
'''%visit_count
    resp = web.Response(text=html, content_type="text/html")
    return resp


### JSON RPC

SCH = {
    "type": "object",
    "properties": {
        "data": {"type": "string"},
    },
}

class rpc_handler(Service):
    @Service.valid(SCH)
    def hello(self, request, data):
        session = yield from get_session(request)
        visit_count = session['visit_count'] if 'visit_count' in session else 1
        print("got:", session.identity, visit_count)
        session['visit_count'] = visit_count + 1
        if data["data"] == "hello":
            for ws in websockets:
                ws.send_str('bla')
            return {"status": "hi", 'visit_count': visit_count - 1}
        return {"status": data}

    def error(self, request, data):
        raise Exception("Error which will catch middleware")

    def no_valid(self, request, data):
        """ Method without validation incommig data """
        return {"status": "ok"}


### WebSockets
class websocket_handler(object):

    def connected(self, ws, session):
        print("websocket: not logged in")

    def message(self, ws, session, msg):
        print("websocket: got message: ", msg)
        ws.send_str(msg + '/answer%d'%session['visit_count'] )

    def closed(self, session):
        print('websocket connection closed')

if __name__ == "__main__":
    c = cirrina.Server("127.0.0.1", 8080)
    c.GET ("/",      default)
    c.RPC ("/jrpc",  rpc_handler)
    c.WS  (websocket_handler)
    c.STATIC("/static", "static/")
    c.run()


