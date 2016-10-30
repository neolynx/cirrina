"""
`cirrina` - Opinionated web framework

Package file

:license: LGPL, see LICENSE for details
"""

from .server import Server
from .client import RPCClient

# expose server class
__all__ = ['Server', 'Client']

# define package metadata
__VERSION__ = '0.1.0'
