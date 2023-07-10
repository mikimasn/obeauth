import DbUtil from "../Utils/DbUtil";
import {Connection} from "mysql";
import {Request} from "express";
import CryptoUtil from "../Utils/CryptoUtil";

export default class {
    private id:number;
    constructor(id:number){
        this.id = id;
    }
    public async revoke(checkrevokable:boolean):Promise<boolean>{
        return new Promise((resolve,reject)=>{
            let conn:Connection = DbUtil.getConnection();
            conn.query(`select * from ${DbUtil.getTablePrefix()}_sessions where session_id = ?`,[this.id],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                if(rows.length==0){
                    resolve(false);
                    return;
                }
                if(checkrevokable){
                    if(rows[0]["revokable"]==0){
                        resolve(false);
                        return;
                    }
                }
                conn.query(`update ${DbUtil.getTablePrefix()}_sessions set revoked = TRUE where session_id = ?`,[this.id],(err)=>{
                    if(err){
                        console.log(err);
                        reject();
                        return;
                    }
                    resolve(true);
                })
            });
        })
       
        
    }
    public static async createSession(scopes:string[],userid:number,revokable:boolean,req:Request,appid:string=""):Promise<string> {
        return new Promise(async (resolve,reject)=>{
            let conn:Connection = DbUtil.getConnection();
            let sdb = scopes.join(",");
            let prove = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            conn.query(`insert into ${DbUtil.getTablePrefix()}_sessions (scopes,revokable,createtime,revoked,owner,token,appid) values (?,?,unix_timestamp(),FALSE,?,?,?)`,[sdb,revokable?1:0,userid,await CryptoUtil.hashPassword(prove),appid],(err,result)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve(result.insertId+":"+prove);
            })
        })
    }
}