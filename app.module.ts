import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from'@nestjs/passport';
//import { AppController } from './app.controller';
import { auth,authSchema } from './auth/auth.service';
import { AuthModule } from './auth/auth.module';
import * as dotenv from "dotenv";
import { MongooseModule } from'@nestjs/mongoose';
dotenv.config({ path: 'C:/authorization/nest-passport/src/jwt_secret.env' })

const JWT_SECRET=process.env.key

@Module({
  imports: [
    PassportModule,
    JwtModule.register({secret:JWT_SECRET,}),
    MongooseModule.forRoot(process.env.ab),
    MongooseModule.forFeature([{ name: auth.name, schema: authSchema }]),
    AuthModule
  ],
  //controllers: [AuthController],
  //providers: [auth],
})
export class AppModule {}
