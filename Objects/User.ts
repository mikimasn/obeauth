import ReturnableHTTP from "./ReturnableHTTP";
import {Connection} from "mysql";
import DbUtil from "../Utils/DbUtil";
import User from "./User";
import {Request} from "express";

export default class implements ReturnableHTTP {
    private id:number;
    constructor(id:number){
        this.id = id;
    }
    public getJsonObject():Promise<JSON> {
        return new Promise((resolve, reject) => {
            let conn: Connection = DbUtil.getConnection();
            conn.query(`select *
                        from ${DbUtil.getTablePrefix()}_applications
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
}