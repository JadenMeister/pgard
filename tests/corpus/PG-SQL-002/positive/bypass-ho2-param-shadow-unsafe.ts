// corpus: expect=PG-SQL-002
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const tableName = "Post";
async function countRows(tableName: string) {
  return prisma.$queryRawUnsafe(`SELECT count(*) FROM "${tableName}"`);
}
export async function handler(req: any, res: any) {
  res.json(await countRows(req.query.table));
}
