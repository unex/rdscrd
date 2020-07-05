import os
import sys
import traceback

from datetime import datetime as dt, timedelta

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from starlette.middleware.sessions import SessionMiddleware

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection
from pymongo import ReturnDocument, ASCENDING, DESCENDING
from bson.objectid import ObjectId

from aiohttp import BasicAuth
from aioauth_client import OAuth2Client, DiscordClient
from secrets import token_urlsafe

from itsdangerous.url_safe import URLSafeSerializer

# DATABASE
MONGO_URI = os.environ.get("MONGO_URI")

# DISCORD API
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")

ALLOWED_SERVER_IDS = os.environ.get("ALLOWED_SERVER_IDS")

# REDDIT API
REDDIT_CLIENT_ID = os.environ.get("REDDIT_CLIENT_ID")
REDDIT_CLIENT_SECRET = os.environ.get("REDDIT_CLIENT_SECRET")

REDDIT_API_BASE_URL = "https://www.reddit.com/api/v1"
REDDIT_OAUTH_BASE_URL = "https://oauth.reddit.com/api/v1"

# APP
REDIRECT_URI_BASE = os.environ.get("REDIRECT_URI_BASE")

SECRET_KEY = os.environ.get('SECRET_KEY', 'this_should_be_configured')
SERIALIZER = URLSafeSerializer(SECRET_KEY)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

mongo: AsyncIOMotorClient
db: AsyncIOMotorCollection

@app.on_event("startup")
async def create_db_client():
    global mongo, db
    mongo = AsyncIOMotorClient(MONGO_URI)
    await mongo.admin.command("ismaster")
    db = mongo.reddiscord


@app.on_event("shutdown")
async def shutdown_db_client():
    await mongo.close()


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return templates.TemplateResponse("error.html", {"request": request, "session": request.session, "exc": exc}, status_code=exc.status_code)


class AdminAuthException(Exception):
    pass


@app.exception_handler(AdminAuthException)
async def admin_exception_handler(request: Request, exc: Exception):
    return RedirectResponse(app.url_path_for('admin_login'))


###############################
#           DEPENDS           #
###############################

async def confirm_login(request: Request, code: str = None, state: str = None, error: str = None) -> DiscordClient:
    if not code:
        return False

    # Check for state and for 0 errors
    state = request.session.get('oauth2_state')

    if error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'There was an error authenticating with discord: {error}'
        )

    #Verify state
    if request.session.get('oauth2_state') != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'State mismatch'
        )

    # Fetch token
    discord = make_discord_session()

    try:
        await discord.get_access_token(code, redirect_uri=REDIRECT_URI_BASE + request.url.path)

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'There was an error authenticating with discord: {e}'
        )

    return discord

async def user(request: Request) -> dict:
    if 'id' in request.session:
        return await db.users.find_one({"_id": ObjectId(SERIALIZER.loads(request.session['id']))})

    return {}

async def auth(request: Request) -> dict:
    if 'admin' in request.session:
        admin = await db.admin.find_one({"_id": ObjectId(SERIALIZER.loads(request.session.get('admin')))})
        if admin: return admin

    raise AdminAuthException()


################################
#            ROUTES            #
################################

@app.get("/")
async def root(request: Request, user = Depends(user)):
    # If a user somehow has a Discord accoutn associated, but no reddit,
    # drop them from the db and start over
    if "discord" in user and 'reddit' not in user:
        await db.users.find_one_and_delete({"_id": ObjectId(SERIALIZER.loads(request.session.get('id')))})
        return RedirectResponse(app.url_path_for('logout'))

    return templates.TemplateResponse("verify.html", {"request": request, "user": user})


@app.get("/v/{token}")
async def from_token(request: Request, token):
    if token:
        user = await db.users.find_one({'token': token})

        if user and 'reddit' not in user:
            request.session["id"] = SERIALIZER.dumps(str(user.get('_id')))
            return RedirectResponse(app.url_path_for('login_reddit'))

    return RedirectResponse(app.url_path_for('root'))


@app.get("/error")
async def test_error(request: Request):
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="test 123")


@app.get("/login/discord")
async def login_discord(request: Request, discord: DiscordClient = Depends(confirm_login), user = Depends(user)):
    if not user or 'reddit' not in user:
        return RedirectResponse(app.url_path_for('logout'))

    if discord:
        # Fetch the user
        try:
            d = await get_discord_user(discord)
        except:
            return RedirectResponse(app.url_path_for('root'))

        # If the user is trying to verify a different Discord than we already have in the db
        if 'discord' in user and user['discord']['id'] != d['id']:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='Error, that account is already affiliated'
            )

        # If the user does not use /v/ it will create a duplicate entry in the db
        # So we remove that here
        # not sure if we can use an aggregate pipeline here....
        dup = await db.users.find_one_and_delete(
            {
                "discord.id": int(d["id"]),
                "reddit": {"$exists": False},
                "token": {"$exists": True}
            }
        )

        # If we update the whole discord obj, it gets rid of the auth
        _id = await db.users.find_one_and_update(
            {"_id": ObjectId(SERIALIZER.loads(request.session.get('id')))},
            {"$set": {
                "discord.id": int(d["id"]),
                "discord.name": d["name"],
                "token": dup.get("token"),
                "verified": True,
                "verified_at": dt.utcnow().timestamp()
            }}
        )

        return RedirectResponse(app.url_path_for('root'))

    else:
        scope = ['identify']
        state = token_urlsafe()
        auth_url = make_discord_session().get_authorize_url(scope=' '.join(scope), redirect_uri=REDIRECT_URI_BASE + request.url.path, state=state)
        request.session['oauth2_state'] = state
        return RedirectResponse(auth_url)


@app.get('/admin/login')
async def admin_login(request: Request, discord: DiscordClient = Depends(confirm_login)):
    if discord:
        guilds = await get_user_guilds(discord)
        managed = get_user_managed_guilds(admin, guilds)
        allowed = list(filter(lambda x: x['id'] in ALLOWED_SERVER_IDS, managed))

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You are not admin on any valid servers :("
            )

        d = await get_discord_user(discord)

        _id = await db.admin.find_one_and_update(
            {"id": d["id"]},
            {"$set": {
                "username": d["username"],
                "discriminator": d["discriminator"],
                "name": d["name"],
                "token": discord.access_token
            }},
            upsert = True,
            return_document=ReturnDocument.AFTER
        )

        # Serialize the UUID from the db and save it to the session
        request.session["admin"] = SERIALIZER.dumps(str(_id.get('_id')))

        return RedirectResponse(app.url_path_for('admin'))

    else:
        scope = ['identify', 'guilds']
        state = token_urlsafe()
        auth_url = make_discord_session().get_authorize_url(scope=' '.join(scope), redirect_uri=REDIRECT_URI_BASE + request.url.path, state=state)
        request.session['oauth2_state'] = state
        return RedirectResponse(auth_url)


@app.get('/login/reddit')
async def login_reddit(request: Request, user = Depends(user), code: str = None, state: str = None, error: str = None):
    if error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'There was an error authenticating with reddit: {error}'
        )

    if code:
        #Verify state
        if request.session.get('oauth2_state') != state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f'State mismatch'
            )

        # Fetch token
        reddit = make_reddit_session()
        auth = BasicAuth(REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET)
        header = {'User-agent': 'Discord auth, /u/RenegadeAI'}
        payload = {
            'redirect_uri': REDIRECT_URI_BASE + request.url.path,
            'grant_type': 'authorization_code',
            'code': code
        }

        reddit_token = await reddit.request('POST', reddit.access_token_url, headers=header, auth=auth, data=payload)

        if not reddit_token or not 'access_token' in reddit_token:
            return RedirectResponse(app.url_path_for('logout'))

        reddit.access_token = reddit_token['access_token']

        # Fetch the user
        ruser = await reddit.request('GET', REDDIT_OAUTH_BASE_URL + "/me", headers=header)

        account_age = ruser['created'] < (dt.utcnow() + timedelta(-7)).timestamp()
        account_karma = ruser['comment_karma'] >= 20 or ruser['link_karma'] >= 10

        if(account_age and account_karma) or ruser['created'] < (dt.utcnow() + timedelta(-30)).timestamp():
            # Save that to the db
            ruser = {k:v for (k,v) in ruser.items() if k in ["id", "name"]}

            # This will happen if they are getting redirected from a token
            if user:
                await db.users.find_one_and_update(
                    {"discord.id": user["discord"]["id"]},
                    {"$set": {
                        "reddit": ruser,
                        "verified": True,
                        "verified_at": dt.utcnow().timestamp()
                    }},
                )

            else:
                # Only save the reddit instance if it doesnt already exist.
                # The users id and name never changes anyway.
                _id = await db.users.find_one_and_update(
                    {"reddit.id": ruser["id"]},
                    {"$setOnInsert": {
                        "reddit": ruser,
                        "verified": False
                    }},
                    upsert = True,
                    return_document=ReturnDocument.AFTER
                )

                # Serialize the UUID from the db and save it to the session
                request.session["id"] = SERIALIZER.dumps(str(_id.get('_id')))

        else:
            if not account_age:
                detail = "Error, your account does not meet the minimum age requirements"
            elif not account_karma:
                detail = "Error, your account does not meet the minimum karma requirements"

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=detail
            )

        return RedirectResponse(app.url_path_for('root'))

    else:
        scope = ['identity']
        state = token_urlsafe()
        auth_url = make_reddit_session().get_authorize_url(scope=','.join(scope), redirect_uri=REDIRECT_URI_BASE + request.url.path, state=state, access_type="offline")
        request.session['oauth2_state'] = state
        return RedirectResponse(auth_url)


@app.get('/logout')
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(app.url_path_for('root'))


@app.get('/admin')
async def admin(request: Request, admin=Depends(auth)):
    return templates.TemplateResponse('admin.html', {'request': request, 'user': admin})


@app.get('/admin/list')
async def user_list(request: Request, admin=Depends(auth)):
    return templates.TemplateResponse('list.html', {'request': request, 'users': await db.users.find(sort=[("verified_at", DESCENDING)]).to_list(1000), 'user': admin})


@app.get('/ajax/stats')
async def ajax_stats(request: Request, admin=Depends(auth), range: str = 'week'):
    today = dt.utcnow()
    upper = today + timedelta(days=1) # Add an extra day, otherwise today wont be included

    if range == 'week':
        lower = today - timedelta(weeks=1)

    if range == 'month':
        lower = today - timedelta(days=30)

    if range == 'year':
        lower = today - timedelta(days=365)

    dates = {}

    for user in await db.users.find({"verified_at": {"$gt": lower.timestamp(), "$lte": upper.timestamp()}}, sort=[('verified_at', ASCENDING)]).to_list(1000):
        date = dt.fromtimestamp(user['verified_at']).date().isoformat()

        if date not in dates:
            dates[date] = 1

        else:
            dates[date] += 1

    return JSONResponse(dates)


@app.route('/ajax/list')
async def ajax_list(request: Request, admin=Depends(auth)):
    users = await db.users.find(sort=[("verified_at", DESCENDING)]).to_list(25)

    return JSONResponse([{
            "id": str(user["_id"]),
            "reddit": user["reddit"]["name"] if 'reddit' in user else None,
            "discord": user["discord"]["name"] if 'discord' in user else None,
            "verified": user.get("verified", None),
            "verified_at": user.get("verified_at", None),
        } for user in users])


################################
#             MISC             #
################################


async def get_discord_user(discord: DiscordClient) -> dict:
    d = await discord.request('GET', 'users/@me')
    d["name"] = d["username"] + "#" + d["discriminator"]
    return d


async def get_user_guilds(discord: DiscordClient) -> dict:
    return await discord.request('GET', 'users/@me/guilds')


def get_user_managed_guilds(user, guilds) -> list:
    return list(filter(lambda g: (g['owner'] is True) or bool((int(g['permissions']) >> 5) & 1), guilds))


def make_discord_session(access_token=None) -> DiscordClient:
    return DiscordClient(
        DISCORD_CLIENT_ID,
        DISCORD_CLIENT_SECRET,
        access_token=access_token
    )


def make_reddit_session() -> OAuth2Client:
    return OAuth2Client(
        REDDIT_CLIENT_ID,
        REDDIT_CLIENT_SECRET,
        base_url=REDDIT_API_BASE_URL,
        authorize_url=REDDIT_API_BASE_URL + "/authorize",
        access_token_url=REDDIT_API_BASE_URL + "/access_token"
    )


###############################
#           FILTERS           #
###############################


def datetimeformat(timestamp):
    return dt.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')

templates.env.filters['datetimeformat'] = datetimeformat
