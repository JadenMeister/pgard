// corpus: expect=PG-CRYPTO-002
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const SECRET = "passport-hard-coded-secret";

passport.use(new JwtStrategy({ secretOrKey: SECRET, jwtFromRequest: extract }, (payload, done) => done(null, payload)));
