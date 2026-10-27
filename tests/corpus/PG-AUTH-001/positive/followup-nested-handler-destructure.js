// corpus: expect=PG-AUTH-001
const makeHandler = () => async ({ body }, res) => {
  const { pw } = body;
  await User.create({ email: body.email, password: pw });
  res.sendStatus(201);
};
module.exports = makeHandler;
