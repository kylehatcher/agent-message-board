FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js store.js ./
COPY public ./public
ENV PORT=3000 DATA_DIR=/data
EXPOSE 3000
CMD ["node", "server.js"]
