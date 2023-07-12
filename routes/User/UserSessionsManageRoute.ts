import {Express} from "express";
import AuthUtil, {AuthenticationResult, UserFlags} from "../../Utils/AuthUtil";
import User from "../../Objects/User";
import Session from "../../Objects/Session";
import ConfigUtil from "../../Utils/ConfigUtil";

export default function (app: Express) {
    app.use("/users/:userid/sessions", async (req, res, next) => {
        let auth = await AuthUtil.authenticate(req, "*");
        if (!auth.valid || !auth.userid) {
            AuthUtil.reject403(res);
            return;
        }
        if (req.params.userid != "me") {
            let user = new User(parseInt(auth.userid));
            let flags = await user.getFlags();
            if ((flags & UserFlags.ADMIN) == 0) {
                AuthUtil.reject403(res);
                return;
            }
        }
        res.locals.authentication = auth;
        next();
    })
    app.get("/users/:userid/sessions", (req, res) => {
        let uid = req.params.userid == "me" ? res.locals.authentication.userid : req.params.userid;
        if (!AuthUtil.validateScope(res.locals.authentication, "user.sessions.list")) {
            AuthUtil.reject403(res);
            return;
        }
        let user = new User(parseInt(uid));
        user.getSessions().then(async(sessions) => {
            let data = await Promise.all(sessions.map(async (session) => await session.getJsonObject()));
            res.status(200).send(data);
        });
    });
    app.delete("/users/:userid/sessions/:sessionid", async (req, res) => {
        if(!AuthUtil.validateScope(res.locals.authentication,"user.sessions.delete")){
            AuthUtil.reject403(res);
            return;
        }
        let session = new Session(parseInt(req.params.sessionid));
        if(await session.isRevoked()){
            res.status(404).send({
                success:false,
                error:"Session not found"
            });
            return;
        }
        session.revoke(req.params.sessionid==res.locals.authentication.sessionid).then((result)=>{
            if(result){
                res.status(200).send({success:true});
                return;
            }
            else{
                AuthUtil.reject403(res);
                return;
            }
        });
    });
    app.post("/users/:userid/sessions",async (req,res)=>{
        if(!AuthUtil.validateScope(res.locals.authentication,"user.sessions.create")){
            AuthUtil.reject403(res);
            return;
        }
        let uid = req.params.userid == "me" ? res.locals.authentication.userid : req.params.userid;
        if(uid!=res.locals.authentication.userid){
            AuthUtil.reject403(res);
            return;
        }
        let authobj:AuthenticationResult = res.locals.authentication;
        if(!authobj.scopes){
            AuthUtil.reject403(res);
            return;
        }
        if(!req.body.scopes||req.body.revokable===undefined){
            res.status(400).send({
                success:false,
                error:"Missing required parameters"
            });
            return;
        }
        if(!Array.isArray(req.body.scopes)||req.body.scopes.length>50){
            res.status(400).send({
                success:false,
                error:"Invalid scopes"
            });
            return;
        }
        if(typeof req.body.revokable!="boolean"){
            res.status(400).send({
                success:false,
                error:"Invalid revokable parameter"
            });
            return;
        }
        let allowedList = ConfigUtil.getConfigKeyList("allowedSessionCreationScopes");
        for(let scope of req.body.scopes){
            if(typeof scope!="string"){
                res.status(400).send({
                    success:false,
                    error:"Invalid scopes"
                });
                return;
            }
            if(!allowedList.includes(scope)){
                res.status(403).send({
                    success:false,
                    error:`You cannot grant a scope ${scope}`
                })
                return;
            }
            if(!AuthUtil.validateScope(authobj,scope)||scope=="*"){
                res.status(403).send({
                    success:false,
                    error:`You cannot grant a scope ${scope}`
                })
                return;
            }
        }
        Session.createSession(req.body.scopes,uid,req.body.revokable,req," ").then((session)=>{
          if(session){
              res.status(200).send({
                  success:true,
                  token:session
              });
              return;
          }
        })

    });
}
