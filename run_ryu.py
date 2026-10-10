#!/usr/bin/env python3
import sys
import collections
import collections.abc

# Fix Python 3.10+ compatibility for legacy Ryu/eventlet dependencies
collections.MutableMapping = collections.abc.MutableMapping
collections.Mapping = collections.abc.Mapping
collections.Callable = collections.abc.Callable

import eventlet.wsgi
if not hasattr(eventlet.wsgi, 'ALREADY_HANDLED'):
    eventlet.wsgi.ALREADY_HANDLED = object()

from ryu.cmd.manager import main

if __name__ == '__main__':
    sys.exit(main())
