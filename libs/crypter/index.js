'use strict';
const crypto = require('crypto');

const IV_LENGTH = 16; // For AES, this is always 16

module.exports = class Crypter {
    static getRandomString(length) {
        length = parseInt(length) || 8;
        return crypto.randomBytes(Math.ceil(length / 2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0, length);
    }

    static encrypt(text, key) {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', new Buffer(key), iv);
        let encrypted = cipher.update(text);

        encrypted = Buffer.concat([encrypted, cipher.final()]);

        return iv.toString('hex') + ':' + encrypted.toString('hex');
    }

    static decrypt(text, key) {
        const textParts = text.split(':');
        const iv = new Buffer(textParts.shift(), 'hex');
        const encryptedText = new Buffer(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', new Buffer(key), iv);
        let decrypted = decipher.update(encryptedText);

        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString();
    }
};