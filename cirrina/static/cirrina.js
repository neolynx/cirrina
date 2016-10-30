function Cirrina (path) {
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
        cirrina.ws = new WebSocket("ws://" + window.location.host + path);
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
        console.log("this.send " + cirrina);
        cirrina.ws.send(msg);
    };

    window.addEventListener("load", this.connect, false);
}
