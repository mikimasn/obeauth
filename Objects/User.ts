import ReturnableHTTP from "./ReturnableHTTP";
import {Connection} from "mysql";
import DbUtil from "../Utils/DbUtil";
import User from "./User";
import {Request} from "express";
import CryptoUtil from "../Utils/CryptoUtil";
import Application from "./Application";
import Session from "./Session";

export default class implements ReturnableHTTP {
    private id:number;
    constructor(id:number){
        this.id = id;
    }
    public getJsonObject():Promise<JSON> {
        return new Promise((resolve, reject) => {
            let conn: Connection = DbUtil.getConnection();
            conn.query(`select id, creationtimestamp, username, flags
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
            password=await CryptoUtil.hashPassword(password);
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
        return new Promise(async (resolve,reject)=>{
            let hashedpassword = await CryptoUtil.hashPassword(password);
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
    public async getPassword():Promise<string>{
        return new Promise((resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`select password from ${DbUtil.getTablePrefix()}_users where id = ?`,[this.id],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve(rows[0].password);
            })
        })
    }
    public async getSessions(revoked:boolean=true):Promise<Array<Session>>{
        return new Promise(async (resolve,reject)=> {
            let conn = DbUtil.getConnection();
            conn.query(`select session_id from ${DbUtil.getTablePrefix()}_sessions where owner = ? AND revoked = ? `, [this.id,revoked?0:1], (err, rows) => {
                if (err) {
                    console.log(err);
                    reject();
                    return;
                }
                let sessions: Array<Session> = [];
                for (let i = 0; i < rows.length; i++) {
                    sessions.push(new Session(rows[i]["session_id"]));
                }
                resolve(sessions);
            })
        })
    }
    public async getRegisterKey(key:string):Promise<string>{
        return new Promise((resolve,reject)=>{
                    let conn = DbUtil.getConnection();
                    conn.query(`select \`value\` from ${DbUtil.getTablePrefix()}_userregister where \`key\` = ?`,[`${this.id}:${key}`],(err,rows)=>{
                        if(err){
                            console.log(err);
                            reject();
                            return;
                        }
                        resolve(rows[0].value);
                    })
                })
    }
    public async setRegisterKey(key:string,value:string):Promise<void>{
        return new Promise((resolve,reject)=>{
            let conn = DbUtil.getConnection();
            conn.query(`insert into ${DbUtil.getTablePrefix()}_userregister (\`key\`,\`value\`) values (?,?) on duplicate `,[`${this.id}:${key}`,value],(err)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve();
            })
        })
    }
}
