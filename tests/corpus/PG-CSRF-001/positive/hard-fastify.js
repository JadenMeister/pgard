// corpus: expect=PG-CSRF-001
const fastify = require("fastify")();
fastify.register(require("@fastify/cookie"));
fastify.register(require("@fastify/session"), { secret: process.env.S, cookie: { secure: true } });

fastify.post("/transfer", async (request, reply) => {
  return { ok: true };
});
