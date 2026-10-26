// corpus: expect=PG-CMD-001
import { exec } from "child_process";
import type { NextApiRequest, NextApiResponse } from "next";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const name = req.query.name as string;
  exec(`nslookup ${name}`, (error, stdout) => res.status(200).send(stdout));
}
