// corpus: expect=none
import express from "express";
import cookieParser from "cookie-parser";
import { doubleCsrf } from "csrf-csrf";

const { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.S! });
const app = express();
app.use(cookieParser());
app.use(doubleCsrfProtection);
app.post("/transfer", (req, res) => res.json({ ok: true }));
