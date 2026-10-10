FROM ghcr.io/puppeteer/puppeteer:latest

USER root
WORKDIR /work
COPY package.json ./
RUN mkdir -p /out /work/.cache && chown -R pptruser:pptruser /work /out
USER pptruser
ENV PUPPETEER_CACHE_DIR=/work/.cache
RUN npm install --omit=dev
COPY --chown=pptruser:pptruser *.mjs ./

# BSKY_TEST_DID, BSKY_TEST_PASSWORD, BSKY_TEST_HANDLE, BSKY_PDS, OUT_DIR
ENTRYPOINT ["node", "bskyapp-login.mjs"]
