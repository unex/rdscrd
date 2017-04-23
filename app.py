import os
from datetime import datetime as dt, timedelta

import requests
import rethinkdb as db
from functools import wraps
from itsdangerous import JSONWebSignatureSerializer
from flask import Flask, render_template, url_for, redirect, g, request, session, send_from_directory, abort

# RETHINKDB
RETHINKDB_HOST = os.environ.get("DOCKHERO_HOST")
RETHINKDB_DB = os.environ.get("RETHINKDB_DB")
RETHINKDB_PASSWORD = os.environ.get("RETHINKDB_PASSWORD")

# # DISCORD API
# DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
# DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
# DISCORD_REDIRECT_BASE_URI = os.environ.get("DISCORD_REDIRECT_BASE_URI")

# DISCORD_API_BASE_URL = 'https://discordapp.com/api'
# AUTHORIZATION_BASE_URL = DISCORD_API_BASE_URL + '/oauth2/authorize'
# TOKEN_URL = DISCORD_API_BASE_URL + '/oauth2/token'

# ALLOWED_SERVER_IDS = os.environ.get("ALLOWED_SERVER_IDS")

# # REDDIT API
# REDDIT_CLIENT_ID = os.environ.get("REDDIT_CLIENT_ID")
# REDDIT_CLIENT_SECRET = os.environ.get("REDDIT_CLIENT_SECRET")
# REDDIT_REDIRECT_URI = os.environ.get("REDDIT_REDIRECT_URI")

# REDDIT_API_BASE_URL = "https://www.reddit.com/api/v1"
# REDDIT_OAUTH_BASE_URL = "https://oauth.reddit.com/api/v1"

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'this_should_be_configured')

# open connection before each request
@app.before_request
def before_request():
    try:
        g.db_conn = db.connect(host=RETHINKDB_HOST, port=28015, db=RETHINKDB_DB, password=RETHINKDB_PASSWORD).repl()
    except db.errors.ReqlDriverError:
        abort(503, "o fucc something is terribly wrong you should tell someone")

# close the connection after each request
@app.teardown_request
def teardown_request(exception):
    try:
        g.db_conn.close()
    except AttributeError:
        pass

@app.route('/')
def index():
    return 'WHY'

if __name__ == '__main__':
    app.run(debug=True)
