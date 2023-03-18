"""
`cirrina` - Opinionated web framework

Simple cirrina server example.

:license: LGPL, see LICENSE for details
"""

import logging
import sys
import cirrina

from aiohttp import web

#: Holds the logger for the current example
logger = logging.getLogger(__name__)

#: Create cirrina app.
app = cirrina.Server()
wspath = '/ws'


@app.auth_handler
async def auth_handler(request, username, password):
    # Example user and password
    if username == 'admin' and password == 'admin':
        return True
    return False


@app.auth_unauthorized
async def auth_unauthorized(request):
    response = web.Response(status=302)
    response.headers['Location'] = '/login.html'
    return response


@app.websocket_connect()
async def websocket_connected(wsclient):
    username = wsclient.cirrina.web_session['username']
    logger.info("websocket: new authenticated connection, user: %s", username)


@app.websocket_message(location=wspath)
async def websocket_message(wsclient, msg):
    logger.info("websocket: got message: '%s'", msg)
    await app.websocket_broadcast(msg)


@app.websocket_disconnect()
async def websocket_closed(wsclient):
    logger.info('websocket connection closed')


@app.http_get('/')
@app.authenticated
async def default(request):
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

    visit_count = 0
    if 'visit_count' in request.cirrina.web_session:
        visit_count = request.cirrina.web_session['visit_count']
    request.cirrina.web_session['visit_count'] = visit_count + 1

    html = '''<!DOCTYPE HTML>
<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">
<script type="text/javascript" src="cirrina.js"></script>
<script type="text/javascript">
  var cirrina = new Cirrina('%s');
  cirrina.onopen = function(ws)
  {
    log("websocket connected" );
    sendmessage("Hello !");
  }
  cirrina.onmessage = function (ws, msg)
  {
    log("server: " + msg );
  }
  cirrina.onclose = function()
  {
    log("websocket disconnected");
  }
  function log(msg)
  {
    textbox = document.getElementById("websocket");
    textbox.innerHTML += msg + "<br/>";
    textbox.scrollTop = textbox.scrollHeight;
  }
  function sendmessage( msg )
  {
    log("client: " + msg );
    cirrina.send( msg );
    document.getElementById('text').value = "";
    document.getElementById('text').focus();
  }

  function upload()
  {
    var form = document.getElementById('upload_form');
    var form_data = new FormData(form);
    var http = new XMLHttpRequest();
    http.open('POST', '/upload', true);
    http.addEventListener('load', function(event) {
       if (http.status >= 200 && http.status < 300) {
         console.log('file uploaded');
       } else {
         alert('Upload failed !');
       }
    });
    if(http.upload) {
      http.upload.onprogress = function(e) {
        var done = e.position || e.loaded, total = e.totalSize || e.total;
        console.log('upload progress: ' + done + ' / ' + total + ' = ' + (Math.floor(done/total*1000)/10) + '%%');
      };
    }
    http.send(form_data);
  }
</script>
</head>
<body>
 <h1>Cirrina Example</h1>
 Page Visit Count: %d <br/>
 <h2>File Upload Example</h2>
 <form id="upload_form" action="/upload" method="post" accept-charset="utf-8" enctype="multipart/form-data">
    <label for="file">Select File: </label>
    <input id="file" name="file" type="file" value=""/><br/>
    <button type="button" onclick="upload();">Upload</button>
 </form>

 <h2>Websocket Example</h2>
 <div id="websocket" style="width: 500px; border: 2px solid; padding: 15px; height: 150px; overflow-x: auto;"></div>
 <input type="text" id="text">
 <input type='button' value='Send' onclick="sendmessage(document.getElementById('text').value);">
</body>
</html>
''' % (wspath, visit_count)
    resp = web.Response(text=html, content_type="text/html")
    return resp


@app.startup
def onstart():
    logger.info("starting up...")


@app.shutdown
def onstop():
    logger.info("shutting down...")


@app.http_upload('/upload', upload_dir="upload/")
async def file_upload(request, session, upload_die, filename):
    return web.Response(text='file uploaded: {}'.format(filename))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    port = 8765
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    app.http_static("/", 'static/')
    app.run('0.0.0.0', port, debug=True)
