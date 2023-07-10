import {Express} from "express";
import rateLimit from "express-rate-limit";
import ConfigUtil from "../../Utils/ConfigUtil";
import AuthUtil from "../../Utils/AuthUtil";
import User from "../../Objects/User";
import Session from "../../Objects/Session";

export default function (app:Express){
    let ratelimit = rateLimit({
        windowMs: 60 * 1000,
        max: parseInt(ConfigUtil.getConfigKey("ratelimiting.user")),
        standardHeaders: true,
        legacyHeaders: false,
        message:AuthUtil.rejectRateLimit
    });
    app.use("/user",ratelimit);
    app.use("/user",AuthUtil.authenticateRequest);
    app.get("/user", (req, res) => {
        if(!AuthUtil.validateScope(res.locals.authentication,"user.read")){
            AuthUtil.reject403(res);
            return;
        }
        let user = new User(parseInt(res.locals.authentication.userid));
        user.getJsonObject().then((obj)=>{
            console.log(obj);
            res.status(200).send(obj);
        });
    });
    app.get("/user/session", (req, res) => {
        let session = new Session(res.locals.authentication.sessionid);
        session.getJsonObject().then((obj)=>{
            res.status(200).send(obj);
        });
    })
}
