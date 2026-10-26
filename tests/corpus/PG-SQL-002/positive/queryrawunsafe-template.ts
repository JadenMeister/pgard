// corpus: expect=PG-SQL-002
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

export async function search(req: { query: { name: string } }) {
  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE name = '${req.query.name}'`);
}
