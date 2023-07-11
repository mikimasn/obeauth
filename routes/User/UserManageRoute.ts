import {Express,Request,Response} from "express";
import AuthUtil, {UserFlags} from "../../Utils/AuthUtil";
import User from "../../Objects/User";
import Session from "../../Objects/Session";
import CryptoUtil from "../../Utils/CryptoUtil";
import rateLimit from "express-rate-limit";
import ConfigUtil from "../../Utils/ConfigUtil";
export default function (app:Express){
    let ratelimit = rateLimit({
        windowMs: 10*60 * 1000,
        max: parseInt(ConfigUtil.getConfigKey("ratelimiting.usermanagment")),
        standardHeaders: true,
        legacyHeaders: false,
        message:AuthUtil.rejectRateLimit
    });
    app.use("/users",ratelimit);
    app.patch("/users/:userid/flags",async(req:Request,res:Response)=>{
        let auth = await authorizeuser(req,res,"users.updateflags",true);
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
    app.post("/users/:userid/password",async(req:Request,res:Response)=>{
        if(req.params.userid=="me"){
            let auth = await AuthUtil.authenticate(req,"users.updatepassword");
            if(!auth.valid||!auth.userid){
                AuthUtil.reject403(res);
                return;
            }
            req.params.userid=auth.userid;
            if(!req.body.oldpassword){
                res.status(400).send({
                    "error": 0,
                    "message": "Invalid Data"
                });
                return;
            }
            let user = new User(parseInt(auth.userid));
            let oldpassword = await user.getPassword();
            if(!(await CryptoUtil.validateHash(req.body.oldpassword,oldpassword))){
                res.status(400).send({
                    "error": 0,
                    "message": "Invalid old password"
                });
                return;
            }
        }
        else {
            let auth = await authorizeuser(req, res, "users.updatepassword", true);
            if (!auth)
                return;
        }
        if(!req.body.password){
            res.status(400).send({
                "error": 0,
                "message": "Invalid Data"
            });
            return;
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
        try{
            await new User(id).setPassword(req.body.password);
            res.status(200).send({
                "message": "Password Changed"
            })
        }
        catch (e) {
            AuthUtil.reject500(res);
            console.error(e);

        }
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
    if(!req.headers["authorization"]){
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
    if(requireroot){
        let user = new User(parseInt(auth.userid));
        let flags = await user.getFlags();
        if((flags&UserFlags.ADMIN)==0){
            AuthUtil.reject403(res);
            return false;
        }
    }
    return true;
}
