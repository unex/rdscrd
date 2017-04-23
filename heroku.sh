#!/bin/bash
gunicorn --daemon -w 4 -b 0.0.0.0:$PORT -k gevent --log-file=- app:app
python3 bot.py