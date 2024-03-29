﻿import {Request, Response} from "express";
import DbUtil from "./DbUtil";
import CryptoUtil from "./CryptoUtil";
import {Connection} from "mysql";
import AuthUtil from "./AuthUtil";
export default class{
    public static async authenticate(request:Request,scope:string):Promise<AuthenticationResult> {
        return new Promise(async (resolve, reject) => {
            let conn = DbUtil.getConnection();
            let token = request.headers["authorization"];
            if (!token) {
                resolve({valid:false});
                return;
            }
            let session_id = token.split(":")[0];
            let prove = token.split(":")[1];
            if(!session_id||!prove){
                resolve({valid:false});
                return;
            }
            conn.query(`select *
                        from ${DbUtil.getTablePrefix()}_sessions
                        where session_id = ?
                          and revoked = FALSE`, [session_id], (err, rows) => {
                if (err) {
                    return false;
                }
                if (rows.length == 0)
                    resolve({valid:false});
                else{
                    if(!CryptoUtil.validateHash(prove,rows[0].token)){
                        resolve({valid:false});
                        return;
                    }
                    if(rows[0]["scopes"]!="*"&&scope!="*"){
                        let scopes = rows[0]["scopes"].split(",");
                        if(!scopes.includes(scope)){
                            resolve({valid:false});
                            return;
                        }
                    }
                    conn.query(`Insert into ${DbUtil.getTablePrefix()}_logs (session_id,timestamp,source_ip,endpoint,method) values (?,unix_timestamp(),?,?,?);`,[session_id,request.ip,request.originalUrl,request.method],(err)=>{
                        if(err)
                            console.log(err);
                        conn.query(`Update ${DbUtil.getTablePrefix()}_sessions SET lastuse = ? Where session_id=?;`,[Date.now(),session_id],(err)=>{
                            if(err)
                                console.log(err);
                            let scopes:string[] = rows[0]["scopes"].split(",");
                            resolve({
                                valid:true,
                                sessionid:session_id,
                                userid:rows[0]["owner"],
                                scopes:scopes
                            });
                        })

                    })
                }
            })
        });
    }
    public static reject401(response:Response){
        response.status(401).send({
            "error":10,
            "message":"Unauthorized(no token provided)"
        });
    }
    public static reject403(response:Response){
        response.status(403).send({
            "error":11,
            "message":"Access Refused(propably wrong token or you do not have permission to this resource)"
        });
    }
    public static reject429(response:Response,message?:string){
        response.status(429).send({
            "error":12,
            "message":message?message:"Too many requests"
        });
    }
    public static reject500(response:Response){
        response.status(500).send({
            "error":13,
            "message":"Internal Server Error"
        });
    }
    public static rejectRateLimit(request:Request,response:Response){
        return {
            "error":12,
            "message":"Too many requests"
        }
    }
    public static async createRoot():Promise<void>{
        let conn:Connection = DbUtil.getConnection();
        conn.query(`Select * from ${DbUtil.getTablePrefix()}_users where id = ?`,[1],async (err,rows)=>{
            if(err){
                console.log(err);
                return;
            }
            if(rows.length==0){
                console.log("Creating root user...");
                let password = "";
                for(let i=0;i<10;i++) {
                    password += Math.random().toString(36).substring(2, 7);
                }
                let flags=0;
                for(let flag in UserFlags){
                    flags|=parseInt(UserFlags[flag]);
                }
                conn.query(`Insert into ${DbUtil.getTablePrefix()}_users (username,password,flags,sourceip,creationtimestamp) values (?,?,?,?,unix_timestamp())`,["root",await CryptoUtil.hashPassword(password),flags,"0.0.0.0",""],(err)=>{
                    if(err) {
                        console.log(err);
                    }
                    console.log("Root user created!");
                    console.log("Password: ",password);
                })
            }
        });
    }
    public static async validateUser(username:string,password:string):Promise<UserAuthenticationResult>{
        return new Promise(async (resolve, reject) => {
                    let conn:Connection = DbUtil.getConnection();
                    conn.query(`Select * from ${DbUtil.getTablePrefix()}_users where username = ?`,[username],async (err,rows)=>{
                        if(err){
                            console.log(err);
                            resolve({valid:false});
                            return;
                        }
                        if(rows.length==0){
                            resolve({valid:false});
                            return;
                        }
                        if(!CryptoUtil.validateHash(password,rows[0]["password"])){
                            resolve({valid:false});
                            return;
                        }
                        resolve({
                            valid:true,
                            userid:rows[0]["id"],
                        });
                    });
                });
    }
    public static validateScope(obj:AuthenticationResult,scope:string):boolean{
        if(!obj.valid||!obj.scopes)
            return false;
        return (obj.scopes.includes(scope)||obj.scopes.includes("*"));
    }
    public static authenticateRequest(req:Request,res:Response,next:Function):Promise<void>{
        return new Promise(async (resolve, reject) => {
            if(!req.headers["authorization"]) {
                AuthUtil.reject401(res);
                resolve();
                return;
            }
            let authenticate = await AuthUtil.authenticate(req,"*");
            if(!authenticate.valid||!authenticate.userid){
                AuthUtil.reject403(res);
                resolve();
                return;
            }
            res.locals.authentication = authenticate;
            next();
            resolve();
        });
    }
}
export interface AuthenticationResult {
    valid: boolean;
    sessionid?: string;
    userid?: string;
    scopes?: string[];
}
export interface UserAuthenticationResult{
    valid:boolean;
    userid?:string;
}
export enum UserFlags{
    ADMIN = 1<<0,
    Privileged = 1<<1

}
