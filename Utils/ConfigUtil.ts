export default class{
    public static getConfigKey(key:string):string{
        let config = require("../config.json");
        let path = key.split(".");
        let current = config;
        for(let i = 0; i < path.length; i++){
            current = current[path[i]];
        }
        return current;
    }
}