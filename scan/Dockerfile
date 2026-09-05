# Read-only scan/recon UI (src/ui.ts). Runs the TypeScript directly via tsx.
# better-sqlite3 is a native addon; python3/make/g++ are present so npm ci can
# compile it if no prebuilt binary matches this image's Node ABI.
FROM node:24-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first for layer caching. Dev deps (tsx) are needed at runtime
# because we execute the .ts sources directly.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

ENV UI_HOST=0.0.0.0 \
    UI_PORT=8787 \
    SCAN_DB=/data/scan/scan.db \
    RECON_SEED=/seed/recon.db \
    RECON_DB=/tmp/recon.db
EXPOSE 8787
USER node

# scan.db is mounted from a writable directory, so SQLite can maintain its WAL
# -shm/-wal index in place. recon.db is bind-mounted read-only as a seed at
# $RECON_SEED; because a WAL database needs a writable directory for its -shm,
# we copy the small (~1 MB) recon.db to a writable path ($RECON_DB in /tmp) at
# start and open the copy. The UI opens every DB with an app-layer guard that
# permits only SELECT-class statements, so no source data is ever mutated.
CMD ["sh", "-c", "if [ -f \"$RECON_SEED\" ]; then cp \"$RECON_SEED\" \"$RECON_DB\"; fi; exec node_modules/.bin/tsx src/ui.ts --sqlite \"$SCAN_DB\" --recon-db \"$RECON_DB\" --host \"$UI_HOST\" --port \"$UI_PORT\""]
