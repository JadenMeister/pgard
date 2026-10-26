// corpus: expect=PG-SQL-002
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const status = "active";
export async function byStatus(req: any, res: any) {
  const { status } = req.body;
  res.json(await prisma.$queryRawUnsafe("SELECT * FROM \"User\" WHERE status = '" + status + "'"));
}
