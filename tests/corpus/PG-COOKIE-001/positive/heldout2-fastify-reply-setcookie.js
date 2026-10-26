// corpus: expect=PG-COOKIE-001; known=miss:PG-COOKIE-001:Fastify reply.setCookie() is not recognised
fastify.get("/cb", async (request, reply) => {
  reply.setCookie("session", await issue(request), { path: "/" });
  return { ok: true };
});
