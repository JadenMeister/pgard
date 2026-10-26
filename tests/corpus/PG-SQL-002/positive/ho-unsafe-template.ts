// corpus: expect=PG-SQL-002
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function find(req: any, res: any) {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT * FROM "User" WHERE name = '${req.query.name}'`,
  );
  res.json(rows);
}
