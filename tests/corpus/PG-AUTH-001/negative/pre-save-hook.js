// corpus: expect=none
const bcrypt = require("bcryptjs");

userSchema.pre("save", async function () {
  if (this.isModified("password")) this.password = await bcrypt.hash(this.password, 10);
});
