import {Express,Request,Response} from "express";
import DbUtil from "../../Utils/DbUtil";
import ConfigUtil from "../../Utils/ConfigUtil";
import AuthUtil from "../../Utils/AuthUtil";
import User from "../../Objects/User";
import session from "../../Objects/Session";
let rateLimit = require("express-rate-limit");
export default function (app:Express){
    let ratelimit = rateLimit({
        windowMs: 60 * 1000,
        max: parseInt(ConfigUtil.getConfigKey("ratelimiting.users")),
        standardHeaders: true,
        legacyHeaders: false,
        message:AuthUtil.rejectRateLimit
    });
    app.use("/users",ratelimit);
    app.get("/users",(req:Request,res:Response)=> {
        res.status(200).send({
            "message": "Users Route Working"
        });
    });
    app.post("/users",async(req:Request,res:Response)=> {
        let auth = await AuthUtil.authenticate(req,"users.create");
        if(auth.valid){
            AuthUtil.reject403(res);
            return;
        }
       if(!req.body.username||!req.body.password/*||!req.body.privkey||!req.body.pubkey*/){
              res.status(400).send({
                "error":0,
                "message":"Invalid Data"
              });
       }
       DbUtil.getConnection().query(`Select * from ${DbUtil.getTablePrefix()}_users where sourceip = ?`,[req.ip],async (err,rows)=>{
           if(err){
               console.error(err);
               AuthUtil.reject500(res);
               return;
           }
           let limit = ConfigUtil.getConfigKey("ratelimiting.login.accountsperip");
           if(rows.length>=limit){
               AuthUtil.reject429(res,"Too many accounts");
               return;
           }
           try {
               let user = await User.createUser(req.body.username, req.body.password, req);
               res.status(200).send(await user.getJsonObject());
           }
           catch (err){
                console.error(err);
               AuthUtil.reject500(res);
           }
       })
    });
    app.post("/users/login",async (req:Request,res:Response)=>{
        if(req.headers.token){
            AuthUtil.reject403(res);
            return;
        }
        if(!req.body.username||!req.body.password){
            res.status(400).send({
                "error":0,
                "message":"Invalid Data"
            });
        }
        let auth = await AuthUtil.validateUser(req.body.username,req.body.password);
        if(auth.valid&&auth.userid){
            try {
                let newsession = await session.createSession(["*"], parseInt(auth.userid), true, req);
                res.status(200).send({
                    "token": newsession
                });
            }
            catch (err){
                console.error(err);
                AuthUtil.reject403(res);
                return;
            }

        }
        else {
            AuthUtil.reject403(res);
            return;
        }
    });
}
