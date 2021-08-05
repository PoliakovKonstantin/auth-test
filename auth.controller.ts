import {request, Request, response} from "express"
import { ArgumentMetadata, Catch, Injectable, PipeTransform,ExceptionFilter, ArgumentsHost, UseFilters, CanActivate, ForbiddenException, UseGuards, SetMetadata, Res } from '@nestjs/common';
import { Body, Get, HttpStatus, Post, UsePipes } from '@nestjs/common';
import { UseInterceptors } from '@nestjs/common';
import { Controller,CallHandler, NestInterceptor, ExecutionContext, HttpException,Req,BadRequestException } from '@nestjs/common';
import { catchError, Observable,tap, throwError } from 'rxjs';
import * as Joi from 'joi';
import { ObjectSchema } from'joi';
import { Reflector } from "@nestjs/core";
import {authSchema,auth,authDocument} from "./auth.service"
import * as jwt from 'jsonwebtoken'
import * as dotenv from "dotenv";
import * as bcrypt from 'bcrypt'
import { AuthGuard, PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-strategy";
import { ExtractJwt } from "passport-jwt";
import {JwtStrategy} from "./auth.service"
dotenv.config({ path: 'C:/authorization/nest-passport/src/jwt_secret.env' })
let b:any=0
var token:any
 async function func(password: string | Buffer) {
    const salt = await bcrypt.genSalt();
    const hash =await bcrypt.hash(password, salt)
    //console.log(hash)
    const isMatch =bcrypt.compare(password, hash);
    if (isMatch) return hash
    else{console.error('something broke(')}
}

//func('a').then((value)=>{console.log(value)})
//console.log(b)



@Injectable()
export class JWTAuthGuard extends AuthGuard('jwt'){
    public canActivate(context:ExecutionContext){
        return super.canActivate(context)

    }
    public handleRequest(err,user,info,context:ExecutionContext) {
        try{
            const response=context.switchToHttp().getResponse() 
            if(err) throw Error
            response.json([user,'Аутентификация прошла успешно'])
            return user
        }
        catch(e) {console.error(e)}
        
    }
}

@Catch()
export class ExceptionFilterTest implements ExceptionFilter{
    catch(exception: HttpException, host: ArgumentsHost) {
        const timestamp=new Date().toISOString()
        const http=host.switchToHttp()
        const res=http.getResponse()
        const statusCode=exception.getStatus()
        const errmsg=exception.message
        console.log(timestamp)
        res.status(statusCode).json({
            timestamp: timestamp,
            status:'fail',
            data:errmsg,
            code:statusCode||500
        })
    }

}

export const joi_test=Joi.object({
    email:Joi.string().required(),
    password:Joi.string().required(),
    firstName:Joi.string().required(),
    lastName: Joi.string().required(),
})

@Injectable()
export class Validation implements PipeTransform{
    constructor(private joi:ObjectSchema){}
    transform(value1: any, metadata: ArgumentMetadata) {
        const {error}=this.joi.validate(value1)
        if (error) {
            console.error(error)
            throw new BadRequestException('Validation failed');   
        }
        console.log("Validation passed")
        return value1;
        }
    }






const JWT_SECRET=process.env.key
//const token1=jwt.sign({id:1,login:2,password:3,roles:'admin'},JWT_SECRET)
        //console.log(token1)


@Injectable()
export class AccessGuard implements CanActivate {
  auth: typeof auth;
    static token: any;
  constructor(private readonly reflector: Reflector) { 
      
    this.auth=auth}
  canActivate(context: ExecutionContext, ): boolean | Promise<boolean> | Observable<boolean> {
    /*const currentRouteRole = this.reflector.get<string>('role', context.getHandler());
    console.log(currentRouteRole)*/
    const request = context.switchToHttp().getRequest();
    const response=context.switchToHttp().getResponse();
    const authorization = {email:request.body.email,password:request.body.password};
    //console.log(authorization)
    const email=authorization.email
    const password=authorization.password
    //let token: string
    this.auth.User.find({email},(err: any,docs: any[])=>{
      if (err) throw err
      if (!docs) {response.json("Anything finded"); return false}
      else if(docs){
          docs.map((el: { password: string; id: any; email: any; firstName: any; })=>{
            //console.log('Hi!')
            const isMatch=bcrypt.compare(password,el.password)
            if(isMatch) {
            //console.log('Hi!')
            token=jwt.sign({id:el.id,email:el.email,firstName:el.firstName},JWT_SECRET)
            response.json(token)
            //console.log(token)
            const payload:any = jwt.verify(token, JWT_SECRET);
            /*console.log(payload,'ok')*/}
        else{console.log('Здравствуйте!')}
        })
        //console.log(token,1)
        //const payload:any = jwt.verify(token, JWT_SECRET);
        //console.log(payload)
          
      }  
  })
  return true
}}
       
    

@Controller()
export class AuthController {
    auth: typeof auth;
    constructor(){
        this.auth=auth
        }
    @Post('api/users/signup')
    //@SetMetadata('role','admin')
    //@UseGuards(AccessGuard)
    //@UsePipes(Validation)
    @UseFilters(ExceptionFilterTest)    
    async signUp(@Req() request,@Res() response, @Body(new Validation(joi_test)) body:any) {
        try{
        await this.auth.User.findOne({email:request.body.email},(err: any,doc: any[])=>{
            if (err) console.log(err)
            else{}
            if (doc) {response.json('Учетная запись уже существует!',400);}
            if(!doc){func(request.body.password).then(async (value)=>{request.body.password=value;
                try{await this.auth.User.create(request.body)
                    response.send('ok')}
                    
                catch(err){
                    console.error('error')
                }
                }
            )}
        })
            }
        catch(error) {console.log('something-broke!');return error}
        //console.log(request.body.password)
        
        
        
    }
    @Post('api/users/signin')
    @UseGuards(AccessGuard)
    signIn(@Req() request,@Res() response, body:any){
    }
    @Post('test/jwt/strategy')
    @UseGuards(JWTAuthGuard)
    testStrategy(@Req() request,@Res() response, body:any) {
        return 1
    }
}
