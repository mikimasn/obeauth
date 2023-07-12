import DbUtil from "../Utils/DbUtil";
import Application from "./Application";
import ReturnableHTTP from "./ReturnableHTTP";
import CryptoUtil from "../Utils/CryptoUtil";

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
    private getRegisterKey(key:string):Promise<string>{
        return new Promise(async (resolve,reject)=>{
            let conn = await DbUtil.getConnection();
            conn.query(`select * from ${DbUtil.getTablePrefix()}_appregister where \`key\` = ?`,[`${this.id}:${key}`],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                if(rows.length==0)
                    resolve("");
                else
                    resolve(rows[0]["value"]);
            });
        });
    }
    private setRegisterKey(key:string,value:string):Promise<void>{
        return new Promise(async (resolve,reject)=>{
            let conn = await DbUtil.getConnection();
            conn.query(`insert into ${DbUtil.getTablePrefix()}_appregister (\`key\`,value) values (?,?) on duplicate key update value=?`,[`${this.id}:${key}`,value,value],(err,rows)=>{
                if(err){
                    console.log(err);
                    reject();
                    return;
                }
                resolve();
            });
        });
    }
    public getOauthKey():Promise<string>{
        return this.getRegisterKey("oauthkey");
    }
    public generateOauthKey():Promise<string>{
        return new Promise(async (resolve,reject)=>{
            let key = CryptoUtil.randomHex(32);
            await this.setRegisterKey("oauthkey",key);
            resolve(key);
        })
    }
}
