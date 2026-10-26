// corpus: expect=PG-SQL-002
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function multi(req: any, res: any) {
  let dir = "ASC";
  const out = [];
  for (dir of [].concat(req.query.dirs || [])) {
    out.push(await prisma.$queryRawUnsafe(`SELECT * FROM "Post" ORDER BY id ${dir}`));
  }
  res.json(out);
}
