import {Express,Request,Response} from "express";
import UsersRoute from "./User/UsersRoute";
import ApplicationsRoute from "./Applications/Applications";
export default function (app: Express){
    app.use("/",(req:Request,res:Response,next)=>{
        console.log(req.body);
        if(req.method=="GET"||req.method=="OPTIONS"||req.method=="DELETE") {
            if (Object.keys(req.body).length!==0) {
                res.sendStatus(400);
                return;
            }
        }
        else if(req.method=="POST"||req.method=="PATCH"||req.method=="PUT") {
            if (Object.keys(req.body).length===0) {
                res.sendStatus(400);
                return;
            }
        }
        else{
            res.status(405).send({
                "error":0,
                "message":"Method Not Allowed"
            });
            return;
        }
        next();
    })
    UsersRoute(app);
    ApplicationsRoute(app);
}