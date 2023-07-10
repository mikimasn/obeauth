import {Express} from "express";
import rateLimit from "express-rate-limit";
import ConfigUtil from "../../Utils/ConfigUtil";
import AuthUtil from "../../Utils/AuthUtil";

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
}
