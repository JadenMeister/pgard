// corpus: expect=none
app.post("/subscribe", async (req, res) => {
  await Subscriber.create({ email: req.body.email, topic: req.body.topic });
  res.sendStatus(201);
});
