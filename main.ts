import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as mongoose from 'mongoose'
import * as dotenv from "dotenv";
dotenv.config({ path: 'C:/authorization/nest-passport/src/jwt_secret.env' })
mongoose.connect(process.env.ab)
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
