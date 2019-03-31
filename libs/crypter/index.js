'use strict';
const crypto = require('crypto');
const Helpers = require('../helpers');

const IV_LENGTH = 16; // For AES, this is always 16

const getAvailableAlgorithm = () => {
    const cryptoList = crypto.getCiphers();
    const supportedCiphers = {
        'aes-256-cbc': {
            iv: 16,
        },
    };
    const ciphers = {};

    const matches = Helpers.matchArraysValues(cryptoList, Object.keys(supportedCiphers));

    for (let key of matches){
        if (supportedCiphers[key]){
            ciphers[key] = supportedCiphers[key];
        }
    }
    return ciphers;
};

const availableAlgorithm = getAvailableAlgorithm();

module.exports = class Crypter {
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