// corpus: expect=PG-CSRF-001; known=miss:PG-CSRF-001:only express-session, cookie-session and cookie-parser count as a cookie session, so @fastify/cookie does not
const fastify = require("fastify")();
fastify.register(require("@fastify/cookie"));

fastify.post("/transfer", async (request, reply) => {
  return { ok: true };
});
