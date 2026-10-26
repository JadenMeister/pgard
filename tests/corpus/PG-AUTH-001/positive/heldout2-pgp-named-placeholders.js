// corpus: expect=PG-AUTH-001; known=miss:PG-AUTH-001:pg-promise ${name} placeholders with db.none are not recognised
module.exports = async (req, res) => {
  await db.none("INSERT INTO users(email, password) VALUES(${email}, ${password})", req.body);
  res.sendStatus(201);
};
