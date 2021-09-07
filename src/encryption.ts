import crypto from 'crypto';

interface IConfig {
  algorithm?: string;
  key?: string;
  salt?: string;
  iv?: Buffer;
}

export default class Encryption {
  private algorithm: string;
  private key: Buffer | string;
  private salt: string;
  private iv: Buffer | null;

  constructor(config: IConfig) {
    this.algorithm = config.algorithm || '';
    this.salt = config.salt || '';
    // encode encryption key from utf8 to hex
    const ENCRYPTION_KEY = config.key ? Buffer.from(config.key).toString('hex') : '';
    // initialize key
    this.key = ENCRYPTION_KEY ? Buffer.from(ENCRYPTION_KEY, "hex") : '';
    // initialize IV
    this.iv = config.iv || null;

    // Validate missing config options
    if (!this.algorithm && !this.key) {
      throw Error('Conifguration Error');
    }
  }

    /**
     * Function to encrypt a string into a url slug
     */
    encrypt = (value: string | number, isInt: boolean = false): string => {
      if (!value) {
        throw Error('A value is required!');
      }

      // Initialize the cipher instance
      const cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);

      // Return buffer as a binary encoded string
      let buffer = Buffer.from(value, 'utf8').to_string("binary");

      // Support for small and big ints
      if (isInt) {
        // Set byte auto padding to false
        cipher.setAutoPadding(false);

        // Allocate Buffer instance 8 bytes
        const buf = Buffer.allocUnsafe(8);

        // Write value to buf instance
        buf.writeBigUInt64BE(BigInt(value));

        // Encode as binary
        buffer = buf.toString("binary");
      }

      // Get encrypted data from the cipher instance
      const firstHalf = cipher.update(buffer, "binary", "base64");
      const secondHalf = cipher.final("base64");
    }

    /**
     * Function to decrypt a url token
     */
    decrypt = (token: string, isInt: boolean = false): string => {

    }
  }
}