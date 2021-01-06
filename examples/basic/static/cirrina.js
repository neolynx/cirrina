function Cirrina(path)
{
    if( ! "WebSocket" in window )
    {
        console.log("WebSocket NOT supported by your Browser!");
        return;
    }

    cirrina = this;

    this.onopen = function(ws)
    {
        console.log("websocket connected" );
    };

    this.onmessage = function (ws, msg)
    {
        console.log("websocket message " + msg);
    };

    this.onclose = function()
    {
        console.log("websocket disconnected");
    };

    this.connect = function()
    {
	var protocol;
	// use wss when https
	if(location.protocol === 'https:') {
	    protocol = 'wss://';
	} else {
	    protocol = 'ws://';
	}

	cirrina.url = protocol + window.location.host + path;
        console.log("cirrina: connecting to " + cirrina.url);
        cirrina.ws = new WebSocket(cirrina.url);
        cirrina.ws.cirrina = cirrina;

        cirrina.ws.onopen = function()
        {
            cirrina.onopen(this);
        };

        cirrina.ws.onmessage = function (evt)
        {
            try {
                var json = JSON.parse(evt.data);
                if(json.status == 401)
                {
                    location.reload();
                    return;
                }
                msg = json.message;
            } catch (e) {
                console.log("websocket non json message: " + evt.data);
                msg = evt.data;
            }

            cirrina.onmessage(this, msg);
        };

        cirrina.ws.onclose = function()
        {
            setTimeout(cirrina.connect, 1000);
            cirrina.onclose();
        };
    };

    this.send = function (msg)
    {
        cirrina.ws.send(msg);
    };

    window.addEventListener("load", this.connect, false);
}
