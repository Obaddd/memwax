# Database

- Local URL: DATABASE_URL=postgres://app:${DB_PASSWORD}@localhost:5432/app
- Migrations: `alembic upgrade head`.
- Never run migrations against production from a laptop.
