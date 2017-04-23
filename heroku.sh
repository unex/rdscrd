#!/bin/bash
gunicorn --log-file=- --log-level error --daemon -w 4 -b 0.0.0.0:$PORT -k gevent app:app
python3 bot.py