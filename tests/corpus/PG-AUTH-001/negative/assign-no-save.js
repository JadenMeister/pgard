// corpus: expect=none
module.exports = function toView(req) {
  const view = {};
  view.password = req.body.password;
  return view;
};
