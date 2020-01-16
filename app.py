import os, sys
from datetime import datetime as dt, timedelta

import logging
import requests
import pymongo
from pymongo import MongoClient
from functools import wraps
from requests_oauthlib import OAuth2Session
from itsdangerous import JSONWebSignatureSerializer
from flask import Flask, render_template, url_for, redirect, g, request, session, send_from_directory, abort, jsonify

# DATABASE
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")
DB_DB = os.environ.get("DB_DB")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# DISCORD API
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_BASE_URI = os.environ.get("DISCORD_REDIRECT_BASE_URI")

DISCORD_API_BASE_URL = 'https://discordapp.com/api'
AUTHORIZATION_BASE_URL = DISCORD_API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = DISCORD_API_BASE_URL + '/oauth2/token'

ALLOWED_SERVER_IDS = os.environ.get("ALLOWED_SERVER_IDS")

# REDDIT API
REDDIT_CLIENT_ID = os.environ.get("REDDIT_CLIENT_ID")
REDDIT_CLIENT_SECRET = os.environ.get("REDDIT_CLIENT_SECRET")
REDDIT_REDIRECT_URI = os.environ.get("REDDIT_REDIRECT_URI")

REDDIT_API_BASE_URL = "https://www.reddit.com/api/v1"
REDDIT_OAUTH_BASE_URL = "https://oauth.reddit.com/api/v1"

app = Flask(__name__)

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.DEBUG)
# app.logger.debug('debug')

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'this_should_be_configured')

mongo = MongoClient(host=DB_HOST, port=int(DB_PORT), username=DB_USER, password=DB_PASSWORD, authSource=DB_DB, authMechanism='SCRAM-SHA-1')
db = mongo[DB_DB]

@app.route('/')
def verify():
    if "reddit_user" in session and "discord_user" in session:
        # Both reddit and discord instances are avaliable, good to go.
        pass
    elif "reddit_user" in session:
        # Attempt to load the discord instance from the reddit instance,
        # if it exists.
        discord_user = db.users.find_one({"reddit.id": session["reddit_user"]["id"]}) or []
        if 'discord' in discord_user:
            session["discord_user"] = {k:v for (k,v) in discord_user["discord"].items() if k in ["id", "name"]}
    elif "discord_user" in session:
        # If a Discord user is logged in, but not reddit, and no
        # reddit account is associated, remove from the db and start over.
        if 'reddit' not in db.users.find_one({"discord.id": session["discord_user"]["id"]}):
            db.users.find_one_and_delete({"discord.id": session["discord_user"]["id"]})

        return redirect(url_for('logout'))

    return render_template('verify.html', session=session)

@app.route('/verify')
def old_verify():
    return redirect(url_for('verify'), code=302)

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Does the user have an api_token?
        api_token = session.get('discord_api_token')

        if api_token is None:
            return redirect(url_for('admin_login'))

        # Does his api_key is in the db?
        user_api_key = db.users.find_one({"discord.id": api_token["user_id"]})["discord"]["api_key"]
        if user_api_key != api_token['api_key']:
            return redirect(url_for('logout'))

        return f(*args, **kwargs)
    return wrapper

@app.route('/login/discord')
def login_discord():
    user = confirm_login(DISCORD_REDIRECT_BASE_URI + "/login/discord")
    if isinstance(user, dict):
        # Save that to the db if there is a reddit instance
        if("reddit_user" in session):
            reddit_user = db.users.find_one({"discord.id": user["id"]})
            discord_user = db.users.find_one({"reddit.id": session["reddit_user"]["id"]})

            # Check if the reddit instance or discord instance already exist in the database.
            # If one already exists but doesnt match the other, return an error
            if (reddit_user and 'reddit' in reddit_user and reddit_user["reddit"]["id"] != session["reddit_user"]["id"]) \
                or (discord_user and 'discord' in discord_user and discord_user["discord"]["id"] != user["id"]):
                return "Error, that account is already affiliated <a href='/'>Return to Verify</a>"

            # If we update the whole discord obj, it gets rid of the auth
            _id = db.users.find_one_and_update(
                {"reddit.id": session["reddit_user"]["id"]},
                {"$set": {
                    "discord.id": user["id"],
                    "discord.username": user["username"],
                    "discord.discriminator": user["discriminator"],
                    "discord.name": user["name"],
                    "verified": True,
                    "verified_at": dt.utcnow().timestamp()
                    }}
            )

            # Save that to the session for easy template access
            session["discord_user"] = {k:v for (k,v) in user.items() if k in ["id", "name"]}

            # Add the ID of that to the queue
            db.queue.insert_one({'ref': _id["_id"]})

        return redirect(url_for('verify'))

    if user:
        return user

    else:
        scope = ['identify']
        discord = make_discord_session(scope=scope, redirect_uri=DISCORD_REDIRECT_BASE_URI + "/login/discord")
        authorization_url, state = discord.authorization_url(
            AUTHORIZATION_BASE_URL,
            access_type="offline"
        )
        session['oauth2_state'] = state
        return redirect(authorization_url)

@app.route('/admin/login')
def admin_login():
    user = confirm_login(DISCORD_REDIRECT_BASE_URI + "/admin/login")
    if isinstance(user, dict):
        session["discord_user"] = {k:v for (k,v) in user.items() if k in ["id", "name"]}

        return redirect(url_for('admin'))

    if user:
        return user

    else:
        scope = ['identify', 'guilds']
        discord = make_discord_session(scope=scope, redirect_uri=DISCORD_REDIRECT_BASE_URI + "/admin/login")
        authorization_url, state = discord.authorization_url(
            AUTHORIZATION_BASE_URL,
            access_type="offline"
        )
        session['oauth2_state'] = state
        return redirect(authorization_url)

@app.route('/login/reddit')
def login_reddit():
    # Check for state and for 0 errors
    state = session.get('oauth2_state')
    if request.values.get('error'):
        error = {
            'message': 'There was an error authenticating with reddit: {}'.format(request.values.get('error')),
            'link': '<a href="{}">Return Home</a>'.format(url_for('verify'))
        }
        return render_template('error.html', session=session,  error=error)

    if state and request.args.get('code'):
        # Fetch token
        client_auth = requests.auth.HTTPBasicAuth(REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET)
        post_data = {"grant_type": "authorization_code", "code": request.args.get('code'), "redirect_uri": REDDIT_REDIRECT_URI}
        reddit_token = requests.post(REDDIT_API_BASE_URL + "/access_token", auth=client_auth, data=post_data, headers={'User-agent': 'Discord auth, /u/RenegadeAI'}).json()

        if not reddit_token or not 'access_token' in reddit_token:
            return redirect(url_for('logout'))

        # Fetch the user
        user = get_reddit_user(reddit_token["access_token"])

        if('status' in user):
            if(user['status'] == 'error'):
                return render_template('error.html', session=session,  error=user)

        # Generate api_key from user_id
        serializer = JSONWebSignatureSerializer(app.config['SECRET_KEY'])

        # Store api_key and token
        db.users.update_one(
            {"reddit.id": user['id']},
            {"$set": {"reddit.token": reddit_token}}
        )

        session.permanent = True
        return redirect(url_for('verify'))

    else:
        scope = ['identity']
        reddit = make_reddit_session(scope=scope)
        authorization_url, state = reddit.authorization_url(
            REDDIT_API_BASE_URL + "/authorize",
            access_type="offline"
        )
        session['oauth2_state'] = state
        return redirect(authorization_url)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('verify'))

@app.route('/list')
def user_list_redir():
    return redirect(url_for('user_list'), code=302)

@app.route('/admin')
@require_auth
def admin():
    user_servers = []
    users = []

    user = get_discord_user(session['discord_api_token'])
    guilds = get_user_guilds(session['discord_api_token'])
    servers = sorted(
        get_user_managed_servers(user, guilds),
        key=lambda s: s['name'].lower()
    )

    user_servers = []
    for server in servers:
        #print(server['id'] + ' : ' + server['name'])
        if(server['id'] in ALLOWED_SERVER_IDS):
            user_servers.append(server)

    if(len(user_servers) > 0):
        return render_template('admin.html', user=user, user_servers=user_servers)
    else:
        return "You are not admin on any valid servers :("

@app.route('/admin/list')
@require_auth
def user_list():
    user_servers = []
    users = []

    user = get_discord_user(session['discord_api_token'])
    guilds = get_user_guilds(session['discord_api_token'])
    servers = sorted(
        get_user_managed_servers(user, guilds),
        key=lambda s: s['name'].lower()
    )

    user_servers = []
    for server in servers:
        if(server['id'] in ALLOWED_SERVER_IDS):
            user_servers.append(server)

    if(len(user_servers) > 0):
        return render_template('list.html', users=db.users.find(sort=[("verified_at", pymongo.DESCENDING)]), user=user, user_servers=user_servers)
    else:
        return "You are not admin on any valid servers :("

@app.route('/ajax/stats')
@require_auth
def ajax_stats():
    range = request.args.get('range') or 'week'

    today = dt.utcnow()
    upper = today + timedelta(days=1) # Add an extra day, otherwise today wont be included

    if range == 'week':
        lower = today - timedelta(weeks=1)

    if range == 'month':
        lower = today - timedelta(days=30)

    if range == 'year':
        lower = today - timedelta(days=365)

    dates = {}

    for user in db.users.find({"verified_at": {"$gt": lower.timestamp(), "$lte": upper.timestamp()}}, sort=[('verified_at', pymongo.ASCENDING)]):
        date = dt.fromtimestamp(user['verified_at']).date().isoformat()

        if date not in dates:
            dates[date] = 1

        else:
            dates[date] += 1

    return jsonify(dates)

@app.route('/ajax/list')
@require_auth
def ajax_list():
    users = db.users.find(sort=[("verified_at", pymongo.DESCENDING)], limit=25)

    return jsonify([{
            "id": str(user["_id"]),
            "reddit": user["reddit"]["name"] if 'reddit' in user else None,
            "discord": user["discord"]["name"] if 'discord' in user else None,
            "verified": user.get("verified", None),
            "verified_at": user.get("verified_at", None),
        } for user in users])

''' ------------------------------------------------------------------------- '''

def get_discord_user(token):
    # If it's an api_token, go fetch the discord_token
    if token.get('api_key'):
        token = db.users.find_one({"discord.id": token['user_id']})['discord']['token']

    discord = make_discord_session(token=token)

    req = discord.get(DISCORD_API_BASE_URL + '/users/@me')
    if req.status_code != 200:
        abort(req.status_code)

    user = req.json()

    user["name"] = user["username"] + "#" + user["discriminator"]

    return user

def get_reddit_user(token):
    user = requests.get(REDDIT_OAUTH_BASE_URL + "/me", headers={"Authorization": "bearer " + token, 'User-agent': 'Reddiscord, /u/RenegadeAI'}).json()

    account_age = user['created'] < (dt.utcnow() + timedelta(-7)).timestamp()
    account_karma = user['comment_karma'] >= 20 or user['link_karma'] >= 10

    if(account_age and account_karma) or user['created'] < (dt.utcnow() + timedelta(-30)).timestamp():
        # Save that to the db
        user = {k:v for (k,v) in user.items() if k in ["id", "name"]}

        # Only save the reddit instance if it doesnt already exist.
        # The users id and name never changes anyway.
        db.users.find_one_and_update(
            {"reddit.id": user["id"]},
            {"$setOnInsert": {
                "reddit": user,
                "verified": False,
                "role": False,
                }},
            upsert = True
        )

        # Save that to the session for easy template access
        session["reddit_user"] = user

        return user

    else:
        error = {"status": "error", "link": "<a href='/'>Return Home</a>"}
        if not account_age:
            error['message'] = "Error, your account does not meet the minimum age requirements"
        elif not account_karma:
            error['message'] = "Error, your account does not meet the minimum karma requirements"

        return error

def confirm_login(redirect_uri):
    # Check for state and for 0 errors
    state = session.get('oauth2_state')

    if request.values.get('error'):
        error = {
            'message': 'There was an error authenticating with discord: {}'.format(request.values.get('error')),
            'link': '<a href="{}">Return Home</a>'.format(url_for('verify'))
        }
        return render_template('error.html', session=session,  error=error)

    if not state or not request.args.get('code'):
        return False

    # Fetch token
    discord = make_discord_session(state=state, redirect_uri=redirect_uri)
    discord_token = discord.fetch_token(TOKEN_URL, client_secret=DISCORD_CLIENT_SECRET, authorization_response=request.url.replace('http:', 'https:'))

    if not discord_token:
        return redirect(url_for('verify'))

    # Fetch the user
    user = get_discord_user(discord_token)

    if('status' in user):
        if(user['status'] == 'error'):
            return render_template('error.html', session=session,  error=user)

    else:
        # Generate api_key from user_id
        serializer = JSONWebSignatureSerializer(app.config['SECRET_KEY'])
        api_key = str(serializer.dumps({'user_id': user['id']}))

        db.users.find_one_and_update(
            {"discord.id": user["id"]},
            {"$set": {
                "discord.api_key": api_key,
                "discord.token": discord_token
                }}
        )

        # Store api_token in client session
        discord_api_token = {
            'api_key': api_key,
            'user_id': user['id']
        }
        session.permanent = True
        session['discord_api_token'] = discord_api_token

        return user

def get_user_guilds(token):
    # If it's an api_token, go fetch the discord_token
    if token.get('api_key'):
        user_id = token['user_id']
        token = db.users.find_one({"discord.id": user_id})['discord']['token']

    else:
        user_id = get_discord_user(token)['id']

    discord = make_discord_session(token=token)

    req = discord.get(DISCORD_API_BASE_URL + '/users/@me/guilds')
    if req.status_code != 200:
        abort(req.status_code)

    guilds = req.json()

    return guilds


def get_user_managed_servers(user, guilds):
    return list(filter(lambda g: (g['owner'] is True) or bool((int(g['permissions']) >> 5) & 1), guilds))

def token_updater(discord_token):
    user = get_discord_user(discord_token)
    # Save the new discord_token
    db.users.find_one_and_update(
        {"reddit.id": session["reddit_user"]["id"]},
        {"$set": {"discord.token": discord_token}}
    )

def make_discord_session(token=None, state=None, scope=None, redirect_uri=None):
    return OAuth2Session(
        client_id=DISCORD_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=redirect_uri,
        auto_refresh_kwargs={
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater
    )

def make_reddit_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=REDDIT_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=REDDIT_REDIRECT_URI,
        auto_refresh_kwargs={
            'client_id':None,
            'client_secret':None,
        },
        auto_refresh_url=None,
        token_updater=None
    )

# FILTERS

@app.template_filter('datetimeformat')
def datetimeformat(timestamp):
    return dt.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
