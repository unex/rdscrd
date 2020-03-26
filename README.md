
# Reddiscord

Reddit user verification for the /r/AMD Discord server

## Development

```bash
pipenv run uvicorn app:app --reload
```

## Production

```bash
docker build -t reddiscord ./
docker run --name reddiscord --env-file .env --restart=unless-stopped -p 8000:8000 -d reddiscord
```
