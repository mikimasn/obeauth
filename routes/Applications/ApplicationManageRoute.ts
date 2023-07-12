import {Express} from "express";
import AuthUtil from "../../Utils/AuthUtil";
import Application from "../../Objects/Application";

export default function (app:Express){
    app.use("/applications/:appid",(req,res,next)=>{
       let app = new Application(req.params.appid);
         app.verifyOwnership(res.locals.authentication.userid).then((valid)=>{
                if(valid)
                    next();
                else {
                    AuthUtil.reject403(res);
                    return;
                }
         });
         return;
    });
    app.get("/applications/:appid",(req,res)=>{
        if(!AuthUtil.validateScope(res.locals.authentication,"applications.read")){
            AuthUtil.reject403(res);
            return;
        }
        let app = new Application(req.params.appid);
        app.getJsonObject().then((obj)=>{
            res.status(200).send(obj);
        });
    });
}
