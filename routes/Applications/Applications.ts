import {Express,Request,Response} from "express";
import AuthUtil from "../../Utils/AuthUtil";
import Application from "../../Objects/Application";
let rateLimit = require("express-rate-limit");
import ConfigUtil from "../../Utils/ConfigUtil";
export default function (app:Express){
    let ratelimit = rateLimit({
        windowMs: 60 * 1000, 
        max: parseInt(ConfigUtil.getConfigKey("ratelimiting.applications")), 
        standardHeaders: true, 
        legacyHeaders: false,
        message:AuthUtil.rejectRateLimit
    });
    app.use("/applications",ratelimit);
    app.use("/applications/:appid",(req:Request,res:Response,next)=>{
        AuthUtil.authenticate(req,"applications").then((result)=>{
            if(result.valid && result.userid){
                let app=new Application(req.params.appid);
                app.verifyOwnership(result.userid).then((valid)=>{
                    if(valid)
                        next();
                    else
                        AuthUtil.reject403(res);
                });
                next();
                return;
            }
            AuthUtil.reject403(res);
            
        })
    })
    app.get("/applications",(req:Request,res:Response)=> {
        res.status(200).send({
            "message": "Application Route Working"
        });
    });
    app.post("/applications",async (req:Request,res:Response)=> {
        if(!req.headers["authorization"]) {
            AuthUtil.reject401(res);
            return;
        }
        let authenticate = await AuthUtil.authenticate(req,"applications.create");
        if(!authenticate.valid||!authenticate.userid){
            AuthUtil.reject403(res);
            return;
        }
        if(!req.body.name){
            res.status(400).send({
                "error":0,
                "message":"Invalid Data"
            });
        }
        let app = await Application.createApp(req.body.name,authenticate.userid);
        res.status(200).send(await app.getJsonObject());
        
        
    });
}