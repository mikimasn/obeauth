import {Express} from "express";
import AuthUtil, {UserFlags} from "../../Utils/AuthUtil";
import User from "../../Objects/User";

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
    })
}
