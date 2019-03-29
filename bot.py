import os
import time
import discord
import asyncio
import motor.motor_asyncio
from datetime import datetime as dt
from derw import log

# RETHINKDB
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")
DB_DB = os.environ.get("DB_DB")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# DISCORD
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN")

DISCORD_SERVER = 185565668639244289
VERIFIED_ROLE = 190693397856649216

client = discord.Client()

mongo = motor.motor_asyncio.AsyncIOMotorClient(host=DB_HOST, port=int(DB_PORT), username=DB_USER, password=DB_PASSWORD, authSource=DB_DB, authMechanism='SCRAM-SHA-1')
db = mongo[DB_DB]

async def monitor_db():
    #Monitor DB for changes
    while True:
        try:
            log.info("Monitoring DB")
            async for change in db.queue.watch():
                if change["operationType"] == "insert":
                    user = await db.users.find_one({"_id": change["fullDocument"]["ref"]})

                    if user.get("verified"):
                        await set_verified(user['discord']['id'])

                        db.queue.find_one_and_delete({"_id": change["fullDocument"]['_id']})

        except Exception as e:
            log.error(f'ERROR MONITORING DB: {e}')
            log.warning('WAITING BEFORE TRYING AGAIN')
            time.sleep(5)


@client.event
async def on_ready():
    log.info(f'Logged in as {client.user.name}, {client.user.id}')
    log.info('-----------------------------------------')

    await client.change_presence(activity=discord.Game("reddiscord.synesis.co"))

    #First we check the queue for any old additions if this garbage was down
    backlog = await db.queue.find({}).to_list(None)

    if(backlog):
        log.debug('Catching up, one sec')

        for item in backlog:
            user = await db.users.find_one({"_id": item["ref"]})

            if user.get("verified"):
                await set_verified(user['discord']['id'])

            else:
                log.warning(f'Weird, {item["ref"]} was in the queue but is not verified.')

            db.queue.find_one_and_delete({"_id": item['_id']})

@client.event
async def on_message(message):
    if message.content.startswith('!test'):
        await message.channel.send_message("Test complete")

    elif message.content.startswith('!verification'):
        await message.channel.send_message("https://reddiscord.synesis.co/")

    elif message.content.startswith('!help'):
        await message.channel.send_message('\r\n**!status:** Shows your current verification status.\r\n**!unverify:** Un-links your reddit and Discord accounts.\r\n**!verification:** prints the verification URL.\r\n**!help:** shows this help message.')

    elif message.content.startswith('!whois'):
        if not is_mod(message.author):
            return False

        records = []

        if message.mentions:
            for user in message.mentions:
                data = await db.users.find_one({"discord.id": str(user.id)})

                records.append([
                        f'<@{user.id}>',
                        f'https://reddit.com/u/{data["reddit"]["name"] if data else None}'
                    ])

        if records:
            await message.channel.send('**Whois Results:**\n{}'.format(''.join(str(r[0] + ': ' + (r[1] or 'None') + '\n') for r in records)))

    elif not hasattr(message.channel, "name"):
        if message.content.startswith('!status'):
            data = await db.users.find_one({"discord.id": str(message.author.id)})
            if data:
                await message.channel.send(f'**STATUS**\n \
                    Verified: {data.get("verified", False)} \n \
                    Connected reddit: https://reddit.com/u/{data["reddit"]["name"]} \n \
                    Connected Discord: <@{data["discord"]["id"]}> (duh)')
            else:
                await message.channel.send("This account is not currently verified")

        # elif message.content.startswith('!unverify'):
        #     user = db.table("users").filter({"discord": { "id": message.author.id}})
        #     data = list(user.run())
        #     if(data):

        #         server = client.get_server(DISCORD_SERVER) # Get serer object from ID
        #         role = discord.utils.get(server.roles, id=VERIFIED_ROLE) # Get role object of verified role by ID
        #         member = server.get_member(message.author.id) # Get member object by discord user ID

        #         if not member:
        #             await client.send_message(message.channel, 'You are not a member of the server.')

        #         elif(data[0]['state'] == 'banned'):
        #             await client.send_message(message.channel, 'Banned users cannot unlink their accounts.')

        #         else:
        #             await client.send_message(message.channel, 'Are you sure? Please type !confirm to confirm, or !cancel to cancel.\nThis request will expire in 30 seconds.')

        #             msg = await client.wait_for_message(author=message.author, timeout=30)

        #             if not msg:
        #                 await client.send_message(message.channel, 'Request expired')

        #             elif msg.content.startswith('!confirm'):
        #                 try:
        #                     await client.remove_roles(member, role)

        #                 except Exception as e:
        #                     print("ERROR REMOVING ROLE FOR {0} IN {1}: {2}".format(message.author, server.name, e))

        #                 user.delete().run()
        #                 await client.send_message(message.channel, 'Your accounts have been unlinked.')

        #             elif msg.content.startswith('!cancel'):
        #                 await client.send_message(message.channel, 'Request cancelled.')
        #     else:
        #         await client.send_message(message.channel, 'Error, this account is not currently linked.')

@client.event
async def on_member_join(member):
    data = db.users.find_one({"discord.id": str(member.id)})

    if(data and data.get("verified")):
            await set_verified(member.id)

@client.event
async def on_member_ban(member):
    db.users.find_one_and_update({"discord.id": member.id}, {"verified": False, "banned": True})
    log.info(f'BANNED {member.name + "#" + member.discriminator} ON {member.server.name}')

@client.event
async def on_member_unban(server, user):
    db.users.find_one_and_update({"discord.id": user.id}, {"banned": False})
    log.info(f'UNBANNED {user.name + "#" + user.discriminator} ON {server.name}')

async def set_verified(member_id):
    server = client.get_guild(DISCORD_SERVER) # Get serer object from ID
    role = discord.utils.get(server.roles, id=VERIFIED_ROLE) # Get role object of verified role by ID
    member = server.get_member(int(member_id)) # Get member object by discord user ID

    if member: # Someone might verify before they join the server idk
        try:
            await member.add_roles(role) # Add user as verified
            await member.send("Congratulations! You are now verified!") # Send the verified message
            log.info(f'VERIFIED {member.name}#{member.discriminator} ON {server.name}')

        except Exception as e:
            log.error(f'ERROR ADDING ROLE FOR {member.name}#{member.discriminator} IN {server.name}: {e}') # Log an error if there was a problem

def is_mod(member):
    server = client.get_guild(DISCORD_SERVER)
    member = server.get_member(member.id)
    role = discord.utils.get(member.roles, id=185565928333770752)
    return (member.guild_permissions.administrator or role in member.roles)

while True:
    loop = asyncio.get_event_loop()

    try:
        loop.create_task(monitor_db())
        loop.run_until_complete(client.login(DISCORD_TOKEN))
        loop.run_until_complete(client.connect())

    except Exception as e:
        log.critical(f'Error in main loop: {e}')
        log.warning('WAITING BEFORE TRYING AGAIN')

        # loop.run_until_complete(client.close())

    # finally:
    #     loop.close()

    time.sleep(10)