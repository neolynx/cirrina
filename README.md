<img align="right" src="cirrina.jpg" width="200">

# cirrina

**cirrina** is an opinionated asynchronous web framework based on aiohttp.

**Features**:

- [x] HTTP Server
- [x] Websocket Server
- [x] JSON RPC Server
- [x] Shared sessions between used servers

```python
from cirrina import Server

app = Server()

# Define HTTP route for static files
app.static("/static", Server.DEFAULT_STATIC_PATH)

# enable websocket communication
app.enable_websockets()

if __name__ == '__main__':
    app.run('0.0.0.0')
```

## Installation

Use pip to install *cirrina*:

```bash
pip install cirrina
```
