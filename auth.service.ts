import { ExecutionContext, Injectable } from '@nestjs/common';
import { Prop, Schema, SchemaFactory } from'@nestjs/mongoose';
import { Document } from'mongoose';
import * as mongoose from 'mongoose'
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
export type authDocument =auth & Document
import * as jwt from 'jsonwebtoken'
import * as bcrypt from 'bcrypt'

import * as dotenv from "dotenv";
dotenv.config({ path: 'C:/authorization/nest-passport/src/jwt_secret.env' })

const JWT_SECRET=process.env.key


let token



@Schema()
export class auth {
  static user: any;
  [x: string]: any;
    static User: any;
   constructor(){
    auth.User = mongoose.model("User", authSchema)
    auth.user = new auth.User({ email: "test@gmail.com", password: "qwer", firstName: "testFirstName", lastName: "testLastName" });
}

    
    @Prop()
    email:string
    @Prop()
    password:string
    @Prop()
    firstName:string
    @Prop()
    lastName: string
}
export const authSchema = SchemaFactory.createForClass(auth)

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
    static validate: any;
    constructor(private auth:auth) {
        super({
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          ignoreExpiration: false,
          secretOrKey: JWT_SECRET});
    }
    async validate(payload) {
      let user=payload
      try {
        await auth.User.findOne({email:payload.email,firstName:payload.firstName},(err,doc)=>{
          if (err) { throw Error ;}
          if (doc) {user=doc}
          return user
        })
          return user
      }
      catch(e) {console.error(e)}
      
      }  
  
  
}