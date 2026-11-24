# Docker

- Dev shell: `docker run --rm -it -v ${PWD}:/app -w /app python:3.12 bash`
- Clean up: `docker system prune -f` (only dangling images).
- Compose file is docker-compose.dev.yml.
