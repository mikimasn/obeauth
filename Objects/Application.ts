import DbUtil from "../Utils/DbUtil";
import Application from "./Application";
import ReturnableHTTP from "./ReturnableHTTP";

export default class implements ReturnableHTTP {
    private id: string;

    constructor(id: string) {
        this.id = id;
    }

    public static async createApp(name: string, ownerid: string): Promise<Application> {
        return new Promise(async (resolve, reject) => {
        let conn = await DbUtil.getConnection();
        conn.query(`insert into ${DbUtil.getTablePrefix()}_applications (name, ownerid)
                                       values (?, ?)`, [name, ownerid], (err, result) => {
            if (err) {
                console.log(err);
                reject();
                return;
            }
            resolve(new Application(result.insertId));
        })
            
        });
    }
    public getJsonObject():Promise<JSON>{
        return new Promise(async (resolve,reject)=>{
            let conn = await DbUtil.getConnection();
            conn.query(`select * from ${DbUtil.getTablePrefix()}_applications where id = ?`,[this.id],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve(rows[0]);
            })
        })
        
    }
    public verifyOwnership(userid:string):Promise<boolean>{
        return new Promise(async (resolve,reject)=>{
            let conn = await DbUtil.getConnection();
            conn.query(`select * from ${DbUtil.getTablePrefix()}_applications where id = ? and ownerid = ?`,[this.id,userid],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                if(rows.length==0)
                    resolve(false);
                else
                    resolve(true);
            })
        })
    }
}