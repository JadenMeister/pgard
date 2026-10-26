// corpus: expect=low
import { Prisma, PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const COLUMNS: Record<string, string> = { new: '"createdAt"', name: '"name"' };

export function sorted(req: any) {
  const column = COLUMNS[String(req.query.sort)] ?? '"createdAt"';
  return prisma.$queryRaw(Prisma.sql`SELECT * FROM "Post" ORDER BY ${Prisma.raw(column)}`);
}
