import crypto from 'crypto';

interface IConfig {
  algorithm: string;
  encriptionKey?: string;
  salt: string;
  iv?: Buffer;
}

export default class Encryption {
  private algorithm: string;
  private password: Buffer;
  private salt: string;
  private iv: Buffer | null;

  constructor(config: IConfig) {
    this.algorithm = config.algorithm;
    this.salt = config.salt;
    // encode encryption key from utf8 to hex
    const ENCRYPTION_KEY = config.encriptionKey ? Buffer.from(config.encriptionKey).toString('hex') : '';
    // initialize key
    this.key = Buffer.from(ENCRYPTION_KEY, "hex");
    // initialize IV
    this.iv = config.iv || null;


    /**
     * Function to encrypt a string into a url slug
     */
    encrypt = (value: string | number, isInt: boolean = false): string => {

    }

    /**
     * Function to decrypt a url token
     */
    decrypt = (token: string, isInt: boolean = false): string => {
      
    }
  }
}