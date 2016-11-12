<img src="cirrina.jpg" width="100">

# cirrina

**cirrina** is an opinionated asynchronous web framework based on aiohttp.

```python
from cirrina import Server

app = Server()

# Define HTTP route for static files
app.static("/static", Server.DEFAULT_STATIC_PATH)

# enable websocket communication
app.enable_websockets()

# enable JSON RPC communication
app.enable_rpc('/jrpc')

if __name__ == '__main__':
    app.run('0.0.0.0')
```

## Installation

Use pip to install *cirrina*:

```bash
pip install cirrina
```
