import cirrina
from aiohttp import web
import json


class MyServer(cirrina.Server):

    def __init__(self, bind, port):
        cirrina.Server.__init__(self, bind, port)
        self.GET ("/",      self.default)
        self.RPC ("/jrpc")
        self.WS()
        self.STATIC("/static", cirrina.Server.DEFAULT_STATIC_PATH)


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
        print("websocket: new authenticated connection, user:", session['username'])

    def websocket_message(self, ws, session, msg):
        print("websocket: got message: ", msg)
        self.websocket_broadcast(msg)

    def websocket_closed(self, session):
        print('websocket connection closed')


    ### JSON RPC

    SCH = {
        "type": "object",
        "properties": {
            "data": {"type": "string"},
        },
    }

    @cirrina.rpc_valid(SCH)
    def hello(self, request, session, data):
        print("jrpc hello called:", data["data"])
        visit_count = session['visit_count'] if 'visit_count' in session else 1
        session['visit_count'] = visit_count + 1
        self.websocket_broadcast(data["data"])
        return {"status": data["data"], 'visit_count': visit_count - 1}


if __name__ == "__main__":
    c = MyServer("0.0.0.0", 8080)
    c.run()


