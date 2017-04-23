import os, sys
from datetime import datetime as dt, timedelta

import requests
import rethinkdb as db
from functools import wraps
from requests_oauthlib import OAuth2Session
from itsdangerous import JSONWebSignatureSerializer
from flask import Flask, render_template, url_for, redirect, g, request, session, send_from_directory, abort

# RETHINKDB
RETHINKDB_HOST = os.environ.get("DOCKHERO_HOST")
RETHINKDB_DB = os.environ.get("RETHINKDB_DB")
RETHINKDB_PASSWORD = os.environ.get("RETHINKDB_PASSWORD")

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

print('if u can see this magic has happened')

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
def verify():
    if "reddit_user" in session and "discord_user" in session:
        pass
    elif "reddit_user" in session:
        discord_user = list(db.table("users").filter({ "reddit": {"name": session['reddit_user']}, "method": "web"}).run())[0]
        if 'discord' in discord_user:
            session["discord_user"] = discord_user["discord"]["name"]
    elif "discord_user" in session:
        reddit_user = list(db.table("users").filter({ "discord": {"name": session['discord_user']}, "method": "web"}).run())[0]
        if 'reddit' in reddit_user:
            session["reddit_user"] = reddit_user["reddit"]["name"]

    return render_template('verify.html', session=session)

@app.route('/verify')
def old_verify():
    return redirect(url_for('verify'), code=302)

#Change user state ajax
@app.route('/ajax/change_state', methods=['GET'])
def change_state():
    id = request.args.get('id')
    state = request.args.get('state')
    print(id + " : " + state)
    db.table("users").filter(db.row["id"] == id).update({"state": state, "method": "web"}).run()
    return state

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Does the user have an api_token?
        api_token = session.get('discord_api_token')

        if api_token is None:
            return redirect(url_for('admin_login'))

        # Does his api_key is in the db?
        user_api_key = list(db.table("users").filter({"discord": {"id": api_token['user_id']}, "method": "web"}).run())[0]['discord']['api_key']
        if user_api_key != api_token['api_key']:
            return redirect(url_for('logout'))

        return f(*args, **kwargs)
    return wrapper

@app.route('/login/discord')
def login_discord():
    confirm = confirm_login(DISCORD_REDIRECT_BASE_URI + "/login/discord")
    if confirm:
        return confirm

    else:
        scope = ['identify']
        discord = make_discord_session(scope=scope, redirect_uri=DISCORD_REDIRECT_BASE_URI + "/login/discord")
        authorization_url, state = discord.authorization_url(
            AUTHORIZATION_BASE_URL,
            access_type="offline"
        )
        session['oauth2_state'] = state
        return redirect(authorization_url)

@app.route('/list/login/confirm')
def confirm_admin_login():
    confirm = confirm_login(DISCORD_REDIRECT_BASE_URI + "/list/login/confirm")
    if confirm:
        return confirm

    return redirect(url_for('user_list'))

@app.route('/login/reddit')
def login_reddit():
    # Check for state and for 0 errors
    state = session.get('oauth2_state')
    if request.values.get('error'):
        return redirect(url_for('verify'))

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
                session['error'] = user
                return redirect(url_for('error_page'))

        # Generate api_key from user_id
        serializer = JSONWebSignatureSerializer(app.config['SECRET_KEY'])
        #api_key = str(serializer.dumps({'user_id': user['id']}))
        # Store api_key and token
        db.table("users").filter({"reddit": { "name": user['name']}}).update({ "reddit": { "token": reddit_token}, "method": "web"}).run()
   
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
        #print(server['id'] + ' : ' + server['name'])
        if(server['id'] in ALLOWED_SERVER_IDS):
            user_servers.append(server)

    if(len(user_servers) > 0):
        return render_template('list.html', users=list(db.table("users").run()), states=['verified','unverified','banned'], user=user, user_servers=user_servers)
    else:
        return "You are not admin on any valid servers :("

@app.route('/list/login')
def admin_login():
    scope = ['identify', 'guilds']
    discord = make_discord_session(scope=scope, redirect_uri=DISCORD_REDIRECT_BASE_URI + "/list/login/confirm")
    authorization_url, state = discord.authorization_url(
        AUTHORIZATION_BASE_URL,
        access_type="offline"
    )
    session['oauth2_state'] = state
    return redirect(authorization_url)

@app.route('/error')
def error_page():
    return render_template('error.html', session=session,  error=session['error'])

@app.route('/static/<path:path>')
def send_static(path):
    return '//reddiscord.synesis.co/{}'.format(path)

''' ------------------------------------------------------------------------- '''

def get_discord_user(token):
    # If it's an api_token, go fetch the discord_token
    if token.get('api_key'):
        token = list(db.table("users").filter({"discord":{"id": token['user_id']}}).run())[0]['discord']['token']

    discord = make_discord_session(token=token)

    req = discord.get(DISCORD_API_BASE_URL + '/users/@me')
    if req.status_code != 200:
        abort(req.status_code)

    user = req.json()

    #Build username
    user["name"] = user['username'] + "#" + user['discriminator']

    # Save that to the db
    if("reddit_user" in session):
        data = list(db.table("users").filter({"discord": {"name": user['name']}}).run())

        if('reddit' in data):
            if(data['reddit']['name'] != session['reddit_user']):
                return {"status": "error", "message": "Error, that account is already affiliated", "link": "<a href='/'>Return to Verify</a>"}

        base = db.table("users").filter({"reddit": {"name":session["reddit_user"]}})
        base.update({"discord": user, "state": "verified", "method": "web"}).run()

        # Add the ID of that to the queue
        db.table("queue").insert([{'ref': list(base.run())[0]['id']}]).run()
    else:

        if not(list(db.table("users").filter({"discord": {"name": user['name']}}).run())):
            db.table("users").insert([{"discord": user, "state": "unverified", "method": "web"}]).run()
        else:
            db.table("users").filter({"discord": {"name": user["name"]}}).update({"discord": user, "method": "web"}).run()

    # Save that to the session for easy template access
    session["discord_user"] = user["name"]

    return user

def get_reddit_user(token):
    user = requests.get(REDDIT_OAUTH_BASE_URL + "/me", headers={"Authorization": "bearer " + token, 'User-agent': 'Reddiscord, /u/RenegadeAI'}).json()

    account_age = user['created'] < (dt.utcnow() + timedelta(-7)).timestamp()
    account_karma = user['comment_karma'] >= 20 or user['link_karma'] >= 10

    if(account_age and account_karma) or user['created'] < (dt.utcnow() + timedelta(-30)).timestamp():
        # Save that to the db
        if("discord_user" in session): #If Discord user logged in
            return redirect(url_for('logout'))
            # data = list(db.table("users").filter({"reddit": { "name":user["name"]}}).run())
            #Return error if discord account already affiliated with a different reddit account
            # if('discord_user' in data):
            #     if(data['discord']["name"] != session['discord_user']):
            #         return {"status": "error", "message": "Error, that account is already affiliated", "link": "<a href='/'>Return to Verify</a>"}

            # db.table("users").filter({ "discord": { "name": session["discord_user"]}}).update({"reddit": user, "state": "verified", "method": "web"}).run()
        else:
            if not(list(db.table("users").filter(db.row["reddit"]["name"] == user['name']).run())):
                db.table("users").insert([{"reddit": user, "state": "unverified", "method": "web"}]).run()
            else:
                db.table("users").filter({"reddit": {"name": user['name']}}).update({"reddit": user, "method": "web"}).run()

        # Save that to the session for easy template access
        session["reddit_user"] = user['name']

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
        return redirect(url_for('verify'))

    if not state or not request.args.get('code'):
        return False

    # Fetch token
    discord = make_discord_session(state=state, redirect_uri=redirect_uri)
    discord_token = discord.fetch_token(TOKEN_URL, client_secret=DISCORD_CLIENT_SECRET, authorization_response=request.url.replace('http:', 'https:'))
    
    if not discord_token:
        return redirect(url_for('verify'))

    # Fetch the user
    user = get_discord_user(discord_token)

    print(user['status'])

    if('status' in user):
        if(user['status'] == 'error'):
            session['error'] = user
            return redirect(url_for('error_page'))

    else:
        # Generate api_key from user_id
        serializer = JSONWebSignatureSerializer(app.config['SECRET_KEY'])
        api_key = str(serializer.dumps({'user_id': user['id']}))
        # Store api_key and token
        db.table("users").filter({"discord": {"name": user['name']}}).update({"discord": {"api_key": api_key, "token": discord_token}, "method": "web"}).run()
        # Store api_token in client session
        discord_api_token = {
            'api_key': api_key,
            'user_id': user['id']
        }
        session.permanent = True
        session['discord_api_token'] = discord_api_token

        return redirect(url_for('verify'))

def get_user_guilds(token):
    # If it's an api_token, go fetch the discord_token
    if token.get('api_key'):
        user_id = token['user_id']
        token = list(db.table("users").filter({"discord": { "id": user_id}}).run())[0]['discord']['token']

    else:
        user_id = get_discord_user(token)['id']

    discord = make_discord_session(token=token)

    req = discord.get(DISCORD_API_BASE_URL + '/users/@me/guilds')
    if req.status_code != 200:
        abort(req.status_code)

    guilds = req.json()
    # Saving that to the db
    db.table("users").filter({"discord": {"id": user_id}}).update({"discord": {"guilds": guilds}, "method": "web"}).run()
    return guilds


def get_user_managed_servers(user, guilds):
    return list(filter(lambda g: (g['owner'] is True) or bool((int(g['permissions']) >> 5) & 1), guilds))

def token_updater(discord_token):
    user = get_discord_user(discord_token)
    # Save the new discord_token
    db.table("users").filter({"discord": {"id": user['id']}}).update({"discord": {"token": discord_token}, "method": "web"}).run()

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

if __name__ == '__main__':
    app.run(debug=True)
