// corpus: expect=none
const fastify = require("fastify")();
fastify.register(require("@fastify/cookie"));

fastify.post("/items", async (request, reply) => {
  return { ok: true };
});
