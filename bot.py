import os
import time
import discord
import asyncio
import rethinkdb as db
from datetime import datetime as dt

# RETHINKDB
RETHINKDB_HOST = os.environ.get("DOCKHERO_HOST")
RETHINKDB_DB = os.environ.get("RETHINKDB_DB")
RETHINKDB_PASSWORD = os.environ.get("RETHINKDB_PASSWORD")

# DISCORD
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN")

DISCORD_SERVER = '185565668639244289'
VERIFIED_ROLE = '190693397856649216'

client = discord.Client()

db.connect(RETHINKDB_HOST, 28015, db=RETHINKDB_DB, password=RETHINKDB_PASSWORD).repl()
db.set_loop_type("asyncio")

async def monitor_db():
    #Monitor DB for changes
    while True:
        try:
            conn = await db.connect(RETHINKDB_HOST, 28015, db=RETHINKDB_DB, password=RETHINKDB_PASSWORD) # connect
            feed = await db.table("queue").changes().run(conn) # grab the feed
            print("Monitoring DB")
            while (await feed.fetch_next()): # iterate over the feed
                change = await feed.next() # grab the changes
                if change['new_val']:
                    user = db.table("users").get(change['new_val']['ref']).run()

                    if user['state'] == 'verified':
                        await set_verified(user['discord']['id'])

                    db.table("queue").get(change['new_val']['id']).delete().run()

        except Exception as e:
            print('ERROR MONITORING DB: {}'.format(e))
            print('WAITING BEFORE TRYING AGAIN')
            time.sleep(5)


@client.event
async def on_ready():
    print('Logged in as {0}, {1}'.format(client.user.name, client.user.id))
    print('-----------------------------------------')

    #First we check the queue for any old additions if this garbage was down
    backlog = list(db.table("queue").run())

    if(backlog):
        print('Catching up, one sec')

        for item in backlog:
            user = db.table("users").get(item['ref']).run()

            if user['state'] == 'verified':
                await set_verified(user['discord']['id'])

            else:
                print('Weird, {} was in the queue but is not verified.'.format(item['ref']))

            db.table("queue").get(item['id']).delete().run()

@client.event
async def on_message(message):
    if message.content.startswith('!test'):
        await client.send_message(message.channel, "Test complete")

    elif message.content.startswith('!verification'):
        await client.send_message(message.channel, "https://reddiscord.synesis.co/")

    elif message.content.startswith('!help'):
        await client.send_message(message.channel, '\r\n**!status:** Shows your current verification status.\r\n**!unverify:** Un-links your reddit and Discord accounts.\r\n**!verification:** prints the verification URL.\r\n**!help:** shows this help message.')

    elif message.content.startswith('!whois'):
        if not is_mod(message.author):
            return False

        records = []

        if message.mentions:
            for user in message.mentions:
                data = list(db.table("users").filter({"discord": { "id": user.id}}).run())

                records.append([
                        '<@' + user.id + '>',
                        '/u/' + data[0]['reddit']['name'] if data else None
                    ])

        if records:
            await client.send_message(message.channel, '**Whois Results:**\n{}'.format(''.join(str(r[0] + ': ' + (r[1] or 'None') + '\n') for r in records)))

    elif not message.channel.name:
        if message.content.startswith('!status'):
            data = list(db.table("users").filter({"discord": { "id": message.author.id}}).run())
            if data:
                data = data[0]

                await client.send_message(message.channel, "\nState: {0}\nConnected reddit: /u/{1}\nConnected Discord: {2} (duh)".format(data['state'], data['reddit']['name'], data['discord']['name']))
            else:
                await client.send_message(message.channel, "This account is not currently verified")

        elif message.content.startswith('!unverify'):
            user = db.table("users").filter({"discord": { "id": message.author.id}})
            data = list(user.run())
            if(data):

                server = client.get_server(DISCORD_SERVER) # Get serer object from ID
                role = discord.utils.get(server.roles, id=VERIFIED_ROLE) # Get role object of verified role by ID
                member = server.get_member(message.author.id) # Get member object by discord user ID

                if not member:
                    await client.send_message(message.channel, 'You are not a member of the server.')

                elif(data[0]['state'] == 'banned'):
                    await client.send_message(message.channel, 'Banned users cannot unlink their accounts.')

                else:
                    await client.send_message(message.channel, 'Are you sure? Please type !confirm to confirm, or !cancel to cancel.\nThis request will expire in 30 seconds.')

                    msg = await client.wait_for_message(author=message.author, timeout=30)

                    if not msg:
                        await client.send_message(message.channel, 'Request expired')

                    elif msg.content.startswith('!confirm'):
                        try:
                            await client.remove_roles(member, role)

                        except Exception as e:
                            print("ERROR REMOVING ROLE FOR {0} IN {1}: {2}".format(message.author, server.name, e))

                        user.delete().run()
                        await client.send_message(message.channel, 'Your accounts have been unlinked.')

                    elif msg.content.startswith('!cancel'):
                        await client.send_message(message.channel, 'Request cancelled.')
            else:
                await client.send_message(message.channel, 'Error, this account is not currently linked.')

@client.event
async def on_member_join(member):
    data = list(db.table("users").filter({"discord": { "id": member.id}}).run())

    if(data and data[0]['state'] == 'verified'):
            await set_verified(member.id)
@client.event
async def on_member_ban(member):
    db.table("users").filter({"discord": { "id": member.id}}).update({"state": "banned", "method": "py"}).run()
    print('BANNED {0} ON {1}'.format(member.name + '#' + member.discriminator, member.server.name))

@client.event
async def on_member_unban(server, user):
    db.table("users").filter({"discord": { "id": user.id}}).update({"state": "verified", "method": "py"}).run()
    print('UNBANNED {0} ON {1}'.format(user.name + '#' + user.discriminator, server.name))

async def set_verified(member_id):
    server = client.get_server(DISCORD_SERVER) # Get serer object from ID
    role = discord.utils.get(server.roles, id=VERIFIED_ROLE) # Get role object of verified role by ID
    member = server.get_member(member_id) # Get member object by discord user ID

    if member: # Someone might verify before they join the server idk
        try:
            await client.add_roles(member, role) # Add user as verified
            await client.send_message(member, "Congratulations! You are now verified!") # Send the verified message
            print('VERIFIED {0} ON {1}'.format(member.name + '#' + member.discriminator, server.name))

        except Exception as e:
            print("ERROR ADDING ROLE FOR {0} IN {1}: {2}".format(change['new_val']['discord']['name'], server.name, e)) # Log an error if there was a problem

def is_mod(member):
    role = discord.utils.get(member.server.roles, id='185565928333770752')
    return (member.server_permissions.administrator or role in member.roles)

while True:
    loop = asyncio.get_event_loop()

    try:
        loop.create_task(monitor_db())
        loop.run_until_complete(client.login(DISCORD_TOKEN))
        loop.run_until_complete(client.connect())

    except Exception as e:
        print(str(e))
        print('WAITING BEFORE TRYING AGAIN')

        loop.run_until_complete(client.close())

    finally:
        loop.close()

    time.sleep(10)