import {Express} from "express";
import AuthUtil from "../../Utils/AuthUtil";
import Application from "../../Objects/Application";
import User from "../../Objects/User";
import CryptoUtil from "../../Utils/CryptoUtil";

export default function (app: Express) {
    app.use("/applications/:appid", (req, res, next) => {
        let app = new Application(req.params.appid);
        app.verifyOwnership(res.locals.authentication.userid).then((valid) => {
            if (valid)
                next();
            else {
                AuthUtil.reject403(res);
                return;
            }
        });
        return;
    });
    app.get("/applications/:appid", (req, res) => {
        if (!AuthUtil.validateScope(res.locals.authentication, "applications.read")) {
            AuthUtil.reject403(res);
            return;
        }
        let app = new Application(req.params.appid);
        app.getJsonObject().then((obj) => {
            res.status(200).send(obj);
        });
    });
    app.use("/applications/:appid/oauth2", async (req, res, next) => {
        if (!req.body.password) {
            res.status(400).send({
                success: false,
                error: "Missing password"
            });
            return;
        }
        let user = new User(res.locals.authentication.userid);
        let upassword = await user.getPassword();
        CryptoUtil.validateHash(req.body.password, upassword).then(async (valid) => {
            if (!valid) {
                res.status(403).send({
                    success: false,
                    error: "Invalid password"
                });
                return;
            }
            next();
        });
    })
    app.post("/applications/:appid/oauth2/keys", async (req, res) => {
        if (!AuthUtil.validateScope(res.locals.authentication, "applications.oauth2.keys.get")) {
            AuthUtil.reject403(res);
            return;
        }
        let app = new Application(req.params.appid);
        let secretKey = await app.getOauthKey();
        if (secretKey == "") {
            res.status(404).send({
                success: false,
                error: "You have to generate oauth2 keys first"
            });
        }
        res.status(200).send({
            success: true,
            key: secretKey
        });
    });
    app.put("/applications/:appid/oauth2/keys", async (req, res) => {
        if(!AuthUtil.validateScope(res.locals.authentication,"applications.oauth2.keys.generate")){
            AuthUtil.reject403(res);
            return;
        }
        let app = new Application(req.params.appid);
        let key = await app.generateOauthKey();
        res.status(200).send({
            success:true,
            key:key
        });
    })
}
