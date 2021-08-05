import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { PassportModule } from '@nestjs/passport';
import { auth, authSchema, JwtStrategy  } from './auth.service';
import * as dotenv from "dotenv";
import { JwtModule } from '@nestjs/jwt';
import { AuthController} from './auth.controller';
dotenv.config({ path: 'C:/authorization/nest-passport/src/jwt_secret.env' })

const JWT_SECRET=process.env.key

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: JWT_SECRET,
      signOptions: { expiresIn: '60s' },
    }),
        MongooseModule.forFeature([{ name: auth.name, schema: authSchema }])
      ],
      controllers: [AuthController],
      providers: [auth,JwtStrategy],
})
export class AuthModule {}
