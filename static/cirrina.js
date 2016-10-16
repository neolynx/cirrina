

function Cirrina () {
    if( ! "WebSocket" in window )
    {
        log("WebSocket NOT supported by your Browser!");
        return;
    }

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
        this.ws = new WebSocket("ws://" + window.location.host + "/ws");
        this.ws.cirrina = this;

        this.ws.onopen = function()
        {
            cirrina.onopen(this);
        };

        this.ws.onmessage = function (evt)
        {
            try {
                var msg = JSON.parse(evt.data);
                if(msg.status = 401)
                {
                    location.reload();
                    return;
                }
            } catch (e) {
                console.log("websocket non json message: " + evt.data);
                msg = evt.data;
            }

            cirrina.onmessage(this, msg);
        };

        this.ws.onclose = function()
        {
            setTimeout(cirrina.connect, 1000);
            cirrina.onclose();
        };
    };

    this.send = function (msg)
    {
        this.ws.send(msg);
    };

    this.connect();
}
