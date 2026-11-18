// corpus: expect=PG-CRYPTO-002
import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";

const JWT_SECRET = "nest-app-signing-secret";

@Module({
  imports: [JwtModule.register({ secret: JWT_SECRET, signOptions: { expiresIn: "1h" } })],
})
export class AuthModule {}
