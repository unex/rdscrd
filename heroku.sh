#!/bin/bash
gunicorn --log-level error --daemon -w 4 -b 0.0.0.0:$PORT -k gevent app:app --log-file=-
python3 bot.py