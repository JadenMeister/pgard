// corpus: expect=PG-SQL-002
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const ORDER: Record<string, string> = { newest: '"createdAt" DESC' };
export async function list(req: any, res: any) {
  ORDER[req.query.key] = req.query.expr;
  const rows = await prisma.$queryRaw(
    Prisma.sql`SELECT * FROM "Post" ORDER BY ${Prisma.raw(ORDER[req.query.key])}`,
  );
  res.json(rows);
}
