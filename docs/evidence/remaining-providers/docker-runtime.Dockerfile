FROM node:22.23.3-bookworm-slim AS node
FROM golang:1.27.0-trixie
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && npm install --global pnpm@9.15.9
WORKDIR /workspace
