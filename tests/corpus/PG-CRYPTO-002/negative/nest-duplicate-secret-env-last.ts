// corpus: expect=none
import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";

@Module({
  imports: [JwtModule.register({ secret: "overridden-placeholder", secret: process.env.JWT_SECRET })],
})
export class AuthModule {}
