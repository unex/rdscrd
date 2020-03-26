#! /usr/bin/env sh
exec gunicorn -w 4 -k uvicorn.workers.UvicornH11Worker app:app
