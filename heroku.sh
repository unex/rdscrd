#!/bin/bash
newrelic-admin run-program gunicorn -w 4 -b 0.0.0.0:$PORT -k gevent app:app --daemon
python3 bot.py