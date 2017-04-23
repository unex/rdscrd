#!/bin/bash
gunicorn --daemon -w 4 -b 0.0.0.0:$PORT -k gevent app:app --preload
python3 bot.py