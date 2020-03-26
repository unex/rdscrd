
# Reddiscord

Reddit user verification for the /r/AMD Discord server

## Development

```bash
pipenv run uvicorn app:app --reload
```

## Production

```bash
docker run --name reddiscord --env-file .env --net host --restart=unless-stopped -p 8000:8000 reddiscord
```
