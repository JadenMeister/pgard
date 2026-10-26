// corpus: expect=PG-SQL-002
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function sorted(req: any, res: any) {
  const rows = await prisma.$queryRaw(
    Prisma.sql`SELECT * FROM "Post" ORDER BY ${Prisma.raw(req.query.order)}`,
  );
  res.json(rows);
}
