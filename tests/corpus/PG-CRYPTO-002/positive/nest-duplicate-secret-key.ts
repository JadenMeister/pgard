// corpus: expect=PG-CRYPTO-002
import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";

// The later duplicate key wins in JavaScript, so the hard-coded value is the effective secret.
@Module({
  imports: [JwtModule.register({ secret: process.env.JWT_SECRET, secret: "hard-coded-nest-secret" })],
})
export class AuthModule {}
