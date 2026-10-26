// corpus: expect=PG-SQL-002
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

module.exports = async (req, res) => {
  await prisma.$executeRawUnsafe("DELETE FROM sessions WHERE token = '" + req.body.token + "'");
  res.sendStatus(204);
};
