import {Express,Request,Response} from "express";
import AuthUtil from "../../Utils/AuthUtil";
import User from "../../Objects/User";
import Session from "../../Objects/Session";
export default function (app:Express){
    app.patch("/users/:userid/flags",async(req:Request,res:Response)=>{
        let auth = await authorizeuser(req,res,"users.update",true);
        if(!auth)
            return;
        if(!req.body.flag){
            res.status(400).send({
                "error": 0,
                "message": "Invalid Data"
            });
        }
        let id:number;
        try{
            id = parseInt(req.params.userid);
        }
        catch (err){
            res.status(400).send({
                "error": 0,
                "message": "Invalid Data(invalid userid)"
            });
            return;
        }
        await new User(id).setFlags(req.body.flag);
    });
    app.patch("/users/:userid/password",async(req:Request,res:Response)=>{
        let auth = await authorizeuser(req,res,"users.updatepassword");
        if(!auth)
            return;
        if(!req.body.flag){
            res.status(400).send({
                "error": 0,
                "message": "Invalid Data"
            });
        }
        let id:number;
        try{
            id = parseInt(req.params.userid);
        }
        catch (err){
            res.status(400).send({
                "error": 0,
                "message": "Invalid Data(invalid userid)"
            });
            return;
        }
        await new User(id).setFlags(req.body.flag);
    });
    app.delete("/users/logout",async (req:Request,res:Response)=>{
        let auth=await AuthUtil.authenticate(req,"*");
        if(!auth.valid){
            AuthUtil.reject403(res);
            return;
        }
        if(!auth.sessionid)
            return;
        try{
            let result = await new Session(parseInt(auth.sessionid)).revoke(true);
            if(!result){
                AuthUtil.reject403(res);
                return;
            }
            res.status(200).send({
                "message": "Logged Out"
            });
        }
        catch (e) {
            AuthUtil.reject500(res);
            return;
        }
        
        
    })
}
async function authorizeuser(req:Request,res:Response,scope:string,requireroot:boolean=false):Promise<boolean>{
    if(!req.body.token){
        AuthUtil.reject401(res);
        return false;
    }
    let auth = await AuthUtil.authenticate(req,scope);
    if(!auth.valid){
        AuthUtil.reject403(res);
        return false;
    }
    if(!auth.userid)
        return false;
    if(requireroot)
       if(auth.userid!="1") {
           AuthUtil.reject403(res);
           return false;
       }
    if(!(auth.userid=="1"||auth.userid==req.params.userid)){
        AuthUtil.reject403(res);
        return false;
    }
    return true;
}