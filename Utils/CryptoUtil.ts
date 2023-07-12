import * as bcrypt from 'bcrypt';
import * as fs from 'fs';
import * as crypto from 'crypto';
export default class {
    public static async hashPassword(password: string): Promise<string> {
        return new Promise((resolve, reject) => {
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) {
                    reject(err);
                }
                resolve(hash);
            });
        });
    }
    public static async validateHash(password: string, hash: string): Promise<boolean> {
        return new Promise((resolve, reject) => {
            bcrypt.compare(password, hash, (err, res) => {
                if (err) {
                    reject(err);
                }
                resolve(res);
            });
        });
    }
    public static async prepareKeys():Promise<void>{
        if(!fs.existsSync('pubkey.key')||!fs.existsSync('privkey.key')){
            let keys = await this.generateKeys();
            fs.writeFileSync('pubkey.key',keys.publicKey);
            fs.writeFileSync('privkey.key',keys.privateKey);
            console.log("Keys Generated");
        }
        else
            console.log("Keys Already Existed in the System");
    }
    public static generateKeys() : keys{
            let keypair = crypto.generateKeyPairSync('rsa', {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem'
                }
            });
            return {
                publicKey: keypair.publicKey,
                privateKey: keypair.privateKey
            }
    }
    public static randomHex(length:number):string{
        return crypto.randomBytes(length).toString('hex');
    }
}
interface keys {
    publicKey: string
    privateKey: string;
}
