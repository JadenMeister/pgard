// corpus: expect=PG-CSRF-001
import Fastify from "fastify";
import secureSession from "@fastify/secure-session";

const app = Fastify();
app.register(secureSession, { key: Buffer.from(process.env.K!, "hex") });

app.post("/transfer", async () => ({ ok: true }));
