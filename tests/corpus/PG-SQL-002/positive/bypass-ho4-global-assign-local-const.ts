// corpus: expect=PG-SQL-002
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
function init() {
  const orderBy = '"id"';
  return orderBy;
}
export async function list(req: any, res: any) {
  // @ts-ignore implicit global
  orderBy = req.query.order;
  // @ts-ignore
  res.json(await prisma.$queryRawUnsafe(`SELECT * FROM "Post" ORDER BY ${orderBy}`));
  init();
}
