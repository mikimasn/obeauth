import ReturnableHTTP from "./ReturnableHTTP";
import {Connection} from "mysql";
import DbUtil from "../Utils/DbUtil";
import User from "./User";
import {Request} from "express";
import CryptoUtil from "../Utils/CryptoUtil";
import {hash} from "bcrypt";
import Application from "./Application";

export default class implements ReturnableHTTP {
    private id:number;
    constructor(id:number){
        this.id = id;
    }
    public getJsonObject():Promise<JSON> {
        return new Promise((resolve, reject) => {
            let conn: Connection = DbUtil.getConnection();
            conn.query(`select *
                        from ${DbUtil.getTablePrefix()}_users
                        where id = ?`, [this.id], (err, rows) => {
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve(rows[0]);
            });
        });
    }
    public async setFlags(flags:number):Promise<void>{
        return new Promise((resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`update ${DbUtil.getTablePrefix()}_users set flags = ? where id = ?`,[flags,this.id],(err)=>{
                if(err) {
                    console.log(err);
                    reject();
                    return;
                }
                resolve();
            });
        })
    }
    public static async createUser(username:string,password:string,req:Request):Promise<User>{
        return new Promise(async (resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`insert into ${DbUtil.getTablePrefix()}_users (username,password,sourceip,creationtimestamp,flags) values (?,?,?,unix_timestamp(),0)`,[username,password,req.ip],(err,result)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve(new User(result.insertId));
            })
        })
    }
    public async getFlags():Promise<number>{
        return new Promise((resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`select flags from ${DbUtil.getTablePrefix()}_users where id = ?`,[this.id],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve(rows[0].flags);
            })
        })
    }
    public async setPassword(password:string):Promise<void>{
        let hashedpassword = CryptoUtil.hashPassword(password);
        return new Promise((resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`update ${DbUtil.getTablePrefix()}_users set password = ? where id = ?`,[hashedpassword,this.id],(err)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve();
            })
        })
    }
    public async getApplications():Promise<Array<Application>>{
        return new Promise((resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`select * from ${DbUtil.getTablePrefix()}_applications where ownerid = ?`,[this.id],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                let apps:Array<Application> = [];
                for(let i = 0; i < rows.length; i++){
                    apps.push(new Application(rows[i].id));
                }
                resolve(apps);
            })
        })
    }
}
