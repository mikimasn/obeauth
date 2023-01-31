import User from "./User";
import DbUtil from "../Utils/DbUtil";
import {Connection} from "mysql";

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
}