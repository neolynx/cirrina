"""
`cirrina` - Opinionated web framework

Simple cirrina server example.

:license: LGPL, see LICENSE for details
"""

import logging
import sys
import cirrina
from aiohttp.abc import AbstractAccessLogger

#: Create cirrina app.
app = cirrina.Server()

class AccessLogger(AbstractAccessLogger):

    def _get_username(self, request):
        try:
            return request.cirrina.web_session.get('username')
        except Exception:
            return None

    def log(self, request, response, time):
        username = self._get_username(request)
        self.logger.info(
                f'[{username}] '
                f'{request.remote} '
                f'{request.method} {request.path} {response.status} '
                f'in {time:.6f}s')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    port = 8765
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    app.run('0.0.0.0', port, debug=True, access_log_class=AccessLogger)
