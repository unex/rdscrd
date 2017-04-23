import os

import discord
import asyncio

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN")

client = discord.Client()

@client.event
async def on_ready():
    print('Logged in as {0}, {1}'.format(client.user.name, client.user.id))

    print('-----------------------------------------')

loop = asyncio.get_event_loop()
while True:
    try:
        loop.run_until_complete(client.login(DISCORD_TOKEN))
        loop.run_until_complete(client.connect())

    except Exception as e:
        print(str(e))
        print('WAITING BEFORE TRYING AGAIN')

        loop.run_until_complete(client.close())

    finally:
        loop.close()

    time.sleep(10)