import {Express,Request,Response} from "express";
import AuthUtil, {AuthenticationResult, UserFlags} from "../../Utils/AuthUtil";
import Application from "../../Objects/Application";
let rateLimit = require("express-rate-limit");
import ConfigUtil from "../../Utils/ConfigUtil";
import User from "../../Objects/User";
import ApplicationManageRoute from "./ApplicationManageRoute";
export default function (app:Express){
    let ratelimit = rateLimit({
        windowMs: 60 * 1000,
        max: parseInt(ConfigUtil.getConfigKey("ratelimiting.applications")),
        standardHeaders: true,
        legacyHeaders: false,
        message:AuthUtil.rejectRateLimit
    });
    app.use("/applications",ratelimit);
    app.use("/applications",AuthUtil.authenticateRequest);
    app.get("/applications",(req:Request,res:Response)=> {
        let authobj:AuthenticationResult = res.locals.authentication;
        if(!authobj.userid){
            AuthUtil.reject403(res);
            return;
        }
        if(!AuthUtil.validateScope(authobj,"applications.list")){
            AuthUtil.reject403(res);
            return;
        }
        let user = new User(parseInt(authobj.userid));
        user.getApplications().then((apps)=>{
            res.status(200).send(apps.map(async (app)=>await app.getJsonObject()));
        })
    });
    app.post("/applications",async (req:Request,res:Response)=> {
        let authobj:AuthenticationResult = res.locals.authentication;
        if(!authobj.userid){
            AuthUtil.reject403(res);
            return;
        }
        if(!AuthUtil.validateScope(authobj,"applications.create")){
            AuthUtil.reject403(res);
            return;
        }
        let user = new User(parseInt(res.locals.authentication.userid));
        let flags = await user.getFlags();
        if((flags&UserFlags.Privileged)==0){
            res.status(403).send({
                "error":0,
                "message":"You have to be privileged user to create application"
            })
            return;
        }
        if(!req.body.name){
            res.status(400).send({
                "error":0,
                "message":"Invalid Data"
            });
            return;
        }
        let app = await Application.createApp(req.body.name,authobj.userid);
        res.status(200).send(await app.getJsonObject());
    });
    ApplicationManageRoute(app);
}
