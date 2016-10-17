"""
`cirrina` - Opinionated web framework

Package file

:license: LGPL, see LICENSE for details
"""

from .server import Server, rpc_valid

# expose server class
__all__ = ['Server', 'rpc_valid']

# define package metadata
__VERSION__ = '0.1.0'
