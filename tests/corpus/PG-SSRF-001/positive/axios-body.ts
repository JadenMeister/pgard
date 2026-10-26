// corpus: expect=PG-SSRF-001
import axios from "axios";
import type { Request, Response } from "express";

export async function preview(req: Request, res: Response) {
  const { target } = req.body;
  const page = await axios.get(target);
  res.json({ title: page.data.slice(0, 100) });
}
