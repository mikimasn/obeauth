﻿import {Connection,createConnection} from "mysql";
let config : DbConfig = require("../config.json")["db"];
export default class {
    private static conn : Connection;
    public static async initializedb():Promise<void> {
        await this.createconnection();
        this.conn.query(`create table if not exists ${config.tableprefix}_sessions
            (
                session_id int auto_increment invisible,
                revoked    boolean not null,
                owner      TEXT    not null,
                token      TEXT    not null,
                scopes     TEXT    not null,
                revokable  boolean not null,
                appid      TEXT    null,
                lastuse    long    null,
                createtime long    not null,
                constraint session_id
                    primary key (session_id)
            );
        `);
        this.conn.query(`
            create index user
                on ${config.tableprefix}_sessions (owner(255));
        `).on("error",()=>{});
        this.conn.query(`create table if not exists ${config.tableprefix}_logs
            (
            session_id TEXT null,
            timestamp  long null,
            source_ip  TEXT null,
            endpoint   TEXT null,
            method     TEXT null,
            id int auto_increment invisible,
            constraint id
                primary key (id)
            )`);
        this.conn.query(`
        create table if not exists ${config.tableprefix}_applications
        (
            id      int auto_increment,
            name    TEXT null,
            ownerid int null,
            constraint id
                primary key (id)
        );`);
        this.conn.query(`
            create index owner
                on ${config.tableprefix}_applications (ownerid);
        `).on("error",()=>{});
        this.conn.query(`
        create table if not exists ${config.tableprefix}_users
        (
            id            int auto_increment,
            creationtimestamp long null,
            username          TEXT null,
            flags             int  null,
            password          TEXT null,
            sourceip          TEXT null,
            constraint users_pk
                primary key (id)
        );
        
        
        `);
         this.conn.query(`
                create index password
                    on ${config.tableprefix}_users (password(255));
         `).on("error",()=>{});
        this.conn.query(`
            create table if not exists ${config.tableprefix}_appregister
            (
                \`key\` VARCHAR(50),
                value   text null,
                constraint appregister_pk primary key (\`key\`)
            );
        `);
        this.conn.query(`
            create table if not exists ${config.tableprefix}_userregister
            (
                \`key\` VARCHAR(50) ,
                value TEXT null,
                constraint userregister_pk
                    primary key (\`key\`)
            );
        `);
    }
    public static createconnection():Promise<void>{
        return new Promise((resolve,reject)=> {
            this.conn = createConnection({
                host: config.host,
                user: config.user,
                password: config.password,
                database: config.dbname,
                port: config.port,
                multipleStatements: true
            });
            this.conn.connect((err) => {
                if (err) {
                    console.log("Error connecting to Db");
                    console.error(err);
                    reject();
                }
                console.log("Connection established");
                resolve();
            });
        });
    }
    public static getConnection():Connection{
        return this.conn;
    }
    public static getTablePrefix():string{
        return config.tableprefix;
    }
}
export interface DbConfig {
    host: string;
    user: string;
    password: string;
    dbname: string;

    port: number;
    tableprefix: string;
}
