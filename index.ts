import express, { Express, Request, Response } from 'express';
import router from "./routes/routes";
import CryptoUtil from "./Utils/CryptoUtil";
import DbUtil from "./Utils/DbUtil";
import AuthUtil from "./Utils/AuthUtil";
const app: Express = express();
const port = process.env.PORT || 8080;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
prepair();
router(app);
app.use("/",(req:Request,res:Response)=>{
    res.status(404).send({
        "error":0,
        "message":"404 Not Found"
    });
});
app.listen(port,()=>{
    console.log("Server Running on port: ",port);
})
process.on("unhandledRejection",(reason,p)=>{
    console.log("Unhandled Rejection at: Promise ",p," reason: ",reason);
});
process.on("uncaughtException",(err)=>{
    console.log("Uncaught Exception: ",err);
});
async function prepair(){
    await CryptoUtil.prepareKeys();
    await DbUtil.initializedb();
    await AuthUtil.createRoot();
}