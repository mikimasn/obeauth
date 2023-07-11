import {Express} from "express";
import AuthUtil, {UserFlags} from "../../Utils/AuthUtil";
import User from "../../Objects/User";
import Session from "../../Objects/Session";

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
            })
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
}
