import {Request, Response} from "express";
import DbUtil from "./DbUtil";
import CryptoUtil from "./CryptoUtil";
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
            prove = await CryptoUtil.hashPassword(prove);
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
                    if(!CryptoUtil.validateHash(prove,rows[0].prove)){
                        resolve({valid:false});
                        return;
                    }
                    if(rows[0]["scope"]!="*"){
                        let scopes = rows[0]["scope"].split(",");
                        if(!scopes.includes(scope)){
                            resolve({valid:false});
                            return;
                        }
                    }
                    conn.query(`Insert into ${DbUtil.getTablePrefix()}_logs (session_id,timestamp,source_ip,endpoint,method,data) values (?,unix_timestamp(),?,?,?,?);
                    Update ${DbUtil.getTablePrefix()}_logs SET lastuse = ? Where 'session_id'=?`,[session_id,request.ip,request.originalUrl,request.method,request.body,Date.now(),session_id],(err)=>{
                        if(err)
                            console.log(err);
                        let scopes:string[] = JSON.parse(rows[0]["scope"]);
                        resolve({
                            valid:true,
                            sessionid:session_id,
                            userid:rows[0]["owner"],
                            scopes:scopes
                        });
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
}
export interface AuthenticationResult {
    valid: boolean;
    sessionid?: string;
    userid?: string;
    scopes?: string[];
}