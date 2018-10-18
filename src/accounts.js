/*
 This file is part of web3.js.

 web3.js is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 web3.js is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with web3.js.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * @file accounts.js
 * @author Fabian Vogelsteller <fabian@ethereum.org>
 * @date 2017
 */

"use strict";

const _ = require("underscore");
const Promise = require('any-promise');
const uuid = require('uuid');
const BN = require('bn.js');

const accountsCrypto = require('./accounts-crypto');
const blake2b256 = accountsCrypto.blake2b256;
const keccak256 = accountsCrypto.keccak256;
const nacl = accountsCrypto.nacl;
const scryptsy = accountsCrypto.scrypt;
const cryp = accountsCrypto.node;

const {
    toBuffer,
    prependZeroX,
    removeLeadingZeroX,
    bufferToZeroXHex,
    inputCallFormatter,
    numberToHex,
    isHex,
    isHexStrict
} = require('./accounts-format');

const {
    createKeyPair,
    createA0Address,
    aionPubSigLen
} = require('./accounts-util');

const uuidV4Pattern = require('./accounts-pattern').uuid;

const rlp = require('aion-rlp');
const AionLong = rlp.AionLong;

const isNot = function(value) {
    return (_.isUndefined(value) || _.isNull(value));
};

const Accounts = function Accounts() {
    var _this = this;
    this.wallet = new Wallet(this);
};

const toAionLong = (val) => {
    let num;
    if (
        val === undefined ||
        val === null ||
        val === '' ||
        val === '0x'
    ) {
      return null;
    }

    if (typeof val === 'string') {
        if (
            val.indexOf('0x') === 0 ||
            val.indexOf('0') === 0 ||
            isHex(val) === true ||
            isHexStrict(val) === true
        ) {
            num = new BN(removeLeadingZeroX(val), 16);
        } else {
            num = new BN(val, 10);
        }
    }

    if (typeof val === 'number') {
      num = new BN(val);
    }

    return new AionLong(num);
};

Accounts.prototype._addAccountFunctions = function (account) {
    const _this = this;

    // add sign functions
    account.signTransaction = function signTransaction(tx, callback) {
        return _this.signTransaction(tx, account._privateKey, callback);
    };

    account.sign = function sign(data) {
        return _this.sign(data, account._privateKey);
    };

    account.recover = (message, data) => _this.recover(message, data);

    account.signMessage = (message) => _this.signMessage(message, account._privateKey);

    account.recoverMessage = (message, signature) => _this.recoverMessage(message, signature, account._privateKey);

    account.encrypt = function encrypt(password, options) {
        return _this.encrypt(account._privateKey, password, options);
    };

    account.encryptToRlp = function encryptToRlp(password, options) {
        return _this.encryptToRlp(account._privateKey, password, options);
    };

    return account;
};

// replaces ethlib/lib/account.js#fromPrivate
const createAionAccount = function (opts) {
    const account = createKeyPair({
        privateKey: opts.privateKey,
        entropy: opts.entropy
    });
    account.privateKey = prependZeroX(account._privateKey.toString('hex'));
    account.publicKey = prependZeroX(account._publicKey.toString('hex'));
    account.address = createA0Address(account._publicKey);
    return account;
};

Accounts.prototype.create = function create(entropy) {
    return this._addAccountFunctions(createAionAccount({entropy: entropy}));
};

Accounts.prototype.privateKeyToAccount = function privateKeyToAccount(privateKey) {
    return this._addAccountFunctions(createAionAccount({privateKey: privateKey}));
};

/**
 * Note: has reduced functionality, does not query server if chainId, gasPrice or nonce
 * is not provided by the user. Instead it will reject the promise.
 */
Accounts.prototype.signTransaction = function signTransaction(tx, privateKey, callback) {
    const _this = this;
    let error = false, result;

    const account = this.privateKeyToAccount(privateKey);

    callback = callback || function () {};

    if (!tx) {
        error = new Error('No transaction object given!');

        callback(error, null);
        return Promise.reject(error);
    }

    const signed = (tx) => {

        if (!tx.gas && !tx.gasLimit) {
            error = new Error('"gas" is missing');
        }

        if (tx.nonce  < 0 ||
            tx.gas  < 0 ||
            tx.gasPrice  < 0 ||
            tx.chainId  < 0 ||
            tx.type < 0) {
            error = new Error('Gas, gasPrice, nonce or chainId is lower than 0');
        }

        if (error) {
            callback(error);
            return Promise.reject(error);
        }

        try {
            tx = inputCallFormatter(tx);

            const transaction = tx;
            transaction.to = tx.to || '0x';
            transaction.data = tx.data || '0x';
            transaction.value = tx.value || '0x';
            transaction.timestamp = tx.timestamp || Math.floor(Date.now() / 1000);
            transaction.type = numberToHex(tx.type || 1);

            const rlpEncoded = rlp.encode([
                transaction.nonce,
                transaction.to.toLowerCase(),
                transaction.value,
                transaction.data,
                transaction.timestamp,
                toAionLong(transaction.gas),
                toAionLong(transaction.gasPrice),
                transaction.type
            ]);

            // hash encoded message
            const hash = blake2b256(rlpEncoded);

            // sign with nacl
            const signature = toBuffer(nacl.sign.detached(hash, account._privateKey));

            // verify nacl signature
            if (nacl.sign.detached.verify(hash, signature, account._publicKey) === false) {
                throw new Error('Could not verify signature.');
            }

            // aion-specific signature scheme
            const aionPubSig = Buffer.concat([account._publicKey, signature], aionPubSigLen);

            // add the aion pub-sig
            const rawTx = rlp.decode(rlpEncoded).concat(aionPubSig);

            // re-encode with signature included
            const rawTransaction = rlp.encode(rawTx);

            result = {
                messageHash: bufferToZeroXHex(hash),
                signature: bufferToZeroXHex(aionPubSig),
                rawTransaction: bufferToZeroXHex(rawTransaction)
            };

        } catch(e) {
            callback(e, null);
            return Promise.reject(e);
        }

        callback(null, result);
        return result;
    };

    // Resolve immediately if nonce, chainId and price are provided
    if (tx.nonce !== undefined && tx.gasPrice !== undefined) {
        return Promise.resolve(signed(tx));
    }

    // otherwise if either of these things aren't provided, simply throw
    return Promise.reject(new Error("nonce, chainId or gasPrice was not provided"));
};

/* jshint ignore:start */
// TODO
Accounts.prototype.recoverTransaction = function recoverTransaction(rawTx) {
    throw new Error("unsupported operation");
};
/* jshint ignore:end */

/**
 * Hashing methodology compatible with existing Aion implementation in eth_sign.
 *
 * @param data
 * @returns {string}
 */
const hashMessageAion = function hashMessage(data) {
    const message = isHexStrict(data) ? Buffer.from(data.substring(2), 'hex') : data;
    const messageBuffer = Buffer.from(message);
    const preamble = "\x19Aion Signed Message:\n" + message.length;
    const preambleBuffer = Buffer.from(preamble);
    const ethMessage = Buffer.concat([preambleBuffer, messageBuffer]);
    return "0x" + keccak256(ethMessage).toString('hex');
};

/**
 * Signs an arbitrary data payload, when providing the message note that special
 * treatment is given to strict (0x) prefixed hex strings. These will be
 * automatically converted to Buffers before being input. Otherwise input
 * strings will be treated as UTF-8.
 *
 * @param {string || buffer} data payload to be signed
 * @param {buffer} privateKey
 * @returns {{message: *, messageHash: *, signature: (string|*)}}
 */
Accounts.prototype.sign = function sign(data, privateKey) {
    const account = this.privateKeyToAccount(privateKey);
    const publicKey = account._publicKey;
    const hash = hashMessageAion(data);
    const signature = toBuffer(
        nacl.sign.detached(
            toBuffer(hash),
            toBuffer(privateKey)
        )
    );

    // address + message signature
    const aionPubSig = Buffer.concat(
        [toBuffer(publicKey), toBuffer(signature)],
        aionPubSigLen
    );
    return {
        message: data,
        messageHash: hash,
        signature: bufferToZeroXHex(aionPubSig)
    };
};

/**
 * Recovers the address from an encoded payload, note that this is not the same as
 * simply recovering a signature. The method in which the message is
 * encoded is treated as defined in the sign method as well as the eth_sign
 * API call.
 *
 * @param message
 * @param signature
 * @param {boolean} hasPreamble
 * @returns {*}
 */
Accounts.prototype.recover = function recover(message, signature) {
    const sig = signature || (message && message.signature);
    const publicKey = toBuffer(sig).slice(0, nacl.sign.publicKeyLength);
    const edsig = toBuffer(sig).slice(nacl.sign.publicKeyLength, sig.length);

    const messageHash = hashMessageAion(message);

    // debate whether we throw or return null here
    // rationale is that this is closer to what eth-lib would do
    if (!nacl.sign.detached.verify(toBuffer(messageHash), edsig, publicKey)) {
        throw new Error("invalid signature, cannot recover public key");
    }

    return createA0Address(publicKey);
};

/**
 * Alternative implementation that does not support a pre-amble also
 * does not maintain backwards compatibility with existing AION kernel.
 *
 * Hashing algorithm is also changed to blake2b to be more consistent
 * with expected behaviour from user.
 *
 * @param data
 * @param privateKey
 * @returns {{message: *, messageHash: string, signature: (string|*)}}
 */
Accounts.prototype.signMessage = function signMessage(data, privateKey) {
    const account = this.privateKeyToAccount(privateKey);
    const publicKey = account._publicKey;
    const hash = blake2b256(data);

    const signature = toBuffer(
    nacl.sign.detached(
      toBuffer(hash),
      toBuffer(privateKey)
    )
  );

  // address + message signature
  const aionPubSig = Buffer.concat(
    [toBuffer(publicKey), toBuffer(signature)],
    aionPubSigLen
  );
  return {
    message: data,
    messageHash: hash,
    signature: bufferToZeroXHex(aionPubSig)
  };
};

/**
 * Alternative implementation that does not support pre-amble also
 * does not maintain backwards compatibility with AION kernel.
 *
 *
 * @param message
 * @param signature
 * @returns {*}
 */
Accounts.prototype.recoverMessage = function recoverMessage(message, signature) {
  const sig = signature || (message && message.signature);
  const publicKey = toBuffer(sig).slice(0, nacl.sign.publicKeyLength);
  const edsig = toBuffer(sig).slice(nacl.sign.publicKeyLength, sig.length);

  const messageHash = blake2b256(message);

  // debate whether we throw or return null here
  // rationale is that this is closer to what eth-lib would do
  if (!nacl.sign.detached.verify(toBuffer(messageHash), edsig, publicKey)) {
    throw new Error("invalid signature, cannot recover public key");
  }

  return createA0Address(publicKey);
};

// Taken from https://github.com/ethereumjs/ethereumjs-wallet
Accounts.prototype.decrypt = function (v3Keystore, password, nonStrict) {
    /* jshint maxcomplexity: 10 */

    if(!_.isString(password)) {
        throw new Error('No password given.');
    }

    const json = (_.isObject(v3Keystore)) ? v3Keystore : JSON.parse(nonStrict ? v3Keystore.toLowerCase() : v3Keystore);

    if (json.version !== 3) {
        throw new Error('Not a valid V3 wallet');
    }

    let derivedKey;
    let kdfparams;
    if (json.crypto.kdf === 'scrypt') {
        kdfparams = json.crypto.kdfparams;

        // FIXME: support progress reporting callback
        derivedKey = scryptsy(new Buffer(password), new Buffer(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
    } else if (json.crypto.kdf === 'pbkdf2') {
        throw new Error('pbkdf2 is unsupported by AION keystore format');
    } else {
        throw new Error('Unsupported key derivation scheme');
    }

    const ciphertext = new Buffer(json.crypto.ciphertext, 'hex');

    let mac = blake2b256(Buffer.concat([ derivedKey.slice(16, 32), ciphertext ])).toString('hex');
    if (mac !== json.crypto.mac) {
        throw new Error('Key derivation failed - possibly wrong password');
    }

    const decipher = cryp.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), new Buffer(json.crypto.cipherparams.iv, 'hex'));
    const seed = '0x'+ Buffer.concat([ decipher.update(ciphertext), decipher.final() ]).toString('hex');
    return this.privateKeyToAccount(seed);
};

Accounts.prototype.encrypt = function (privateKey, password, options, fast = true) {
    /* jshint maxcomplexity: 20 */
    const account = this.privateKeyToAccount(privateKey);

    options = options || {};
    const salt = options.salt || cryp.randomBytes(32);
    const iv = options.iv || cryp.randomBytes(16);

    // removed support for pbkdf2, we don't support it on the kernel side
    // doesn't make sense to allow this if we want kernel compatibility
    if ((options.kdf !== null || options.kdf !== undefined) && options.kdf === 'pbkdf2') {
        throw new Error("pbkdf2 format unsupported, use scrypt");
    }

    let derivedKey;
    const kdf = options.kdf || 'scrypt';
    const kdfparams = {
        dklen: options.dklen || 32,
        salt: salt.toString('hex')
    };

    if (kdf === 'pbkdf2') {
        kdfparams.c = options.c || 262144;
        kdfparams.prf = 'hmac-sha256';
        derivedKey = cryp.pbkdf2Sync(new Buffer(password), salt, kdfparams.c, kdfparams.dklen, 'sha256');
    } else if (kdf === 'scrypt') {
        // FIXME: support progress reporting callback
        // support fast identifier, enabled by default, but gives the user the option
        // to switch to iterations identical to kernel side (but this will be CPU intensive)
        kdfparams.n = options.n || fast ? 8192 : 262144; // 2048 4096 8192 16384
        kdfparams.r = options.r || 8;
        kdfparams.p = options.p || 1;
        derivedKey = scryptsy(Buffer.from(password, 'utf-8'), salt, kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
    } else {
        throw new Error('Unsupported kdf');
    }

    const cipher = cryp.createCipheriv(options.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);
    if (!cipher) {
        throw new Error('Unsupported cipher');
    }

    const ciphertext = Buffer.concat([ cipher.update(account._privateKey), cipher.final() ]);

    const mac = blake2b256(
            Buffer.concat(
                [derivedKey.slice(16, 32),
                new Buffer(ciphertext, 'hex')]
            )
        ).toString('hex');

    // add a special clause to uuid, if we detect that uuid field is present
    // and not a hexadecimal number, treat it as the pre-calculated UUID
    let _uuid = null;
    if (typeof options.uuid === "string" && uuidV4Pattern.test(options.uuid)) {
        _uuid = options.uuid;
    } else {
        let randomIn = options.uuid;
        if (typeof randomIn === "string" && isHex(options.uuid)) {
            randomIn = Buffer.from(options.uuid, 'hex');
        }
        _uuid = uuid.v4({ random: randomIn || cryp.randomBytes(16) });
    }

    return {
        version: 3,
        id: _uuid,
        address: account.address.toLowerCase().replace('0x',''),
        crypto: {
            ciphertext: ciphertext.toString('hex'),
            cipherparams: {
                iv: iv.toString('hex')
            },
            cipher: options.cipher || 'aes-128-ctr',
            kdf: kdf,
            kdfparams: kdfparams,
            mac: mac.toString('hex')
        }
    };
};

Accounts.prototype.encryptToRlp = function(privateKey, password, options) {
    return toRlp(this.encrypt(privateKey, password, options));
};


Accounts.prototype.decryptFromRlp = function(buffer, password) {
    return this.decrypt(fromRlp(buffer), password);
};

/**
 * Serializes ksv3 object into buffer
 * https://github.com/aionnetwork/aion/blob/tx_encoding_tests/modMcf/src/org/aion/mcf/account/KeystoreItem.java
 *
 * @method toRlp
 * @param {object} ksv3 (struct)
 * @return {buffer} Keystore (serialized)
 */
const toRlp = (ksv3) => {
    const _kdfparams = [];
    _kdfparams[0] = "";
    _kdfparams[1] = ksv3.crypto.kdfparams.dklen;
    _kdfparams[2] = ksv3.crypto.kdfparams.n;
    _kdfparams[3] = ksv3.crypto.kdfparams.p;
    _kdfparams[4] = ksv3.crypto.kdfparams.r;
    _kdfparams[5] = ksv3.crypto.kdfparams.salt.toString('hex');
    const kdfparams = rlp.encode(_kdfparams);

    const _cipherparams = [];
    _cipherparams[0] = ksv3.crypto.cipherparams.iv.toString('hex');
    const cipherparams = rlp.encode(_cipherparams);

    const _crypto = [];
    _crypto[0] = 'aes-128-ctr';
    _crypto[1] = ksv3.crypto.ciphertext.toString('hex');
    _crypto[2] = 'scrypt';
    _crypto[3] = ksv3.crypto.mac;
    _crypto[4] = cipherparams;
    _crypto[5] = kdfparams;
    const crypto = rlp.encode(_crypto);

    const _keystore = [];
    _keystore[0] = ksv3.id;
    _keystore[1] = 3;
    _keystore[2] = ksv3.address;
    _keystore[3] = crypto;
    const keystore = rlp.encode(_keystore);
    return keystore;
}

/**
 * Deserializes keystore into ksv3 object
 * https://github.com/aionnetwork/aion/blob/tx_encoding_tests/modMcf/src/org/aion/mcf/account/KeystoreItem.java
 *
 * @method fromRlp
 * @param {object} keystore (serialized)
 * @return {buffer} ksv3 (struct)
 */
const fromRlp = (keystore) => {

    // Store return ksv3 object
    const Ksv3 = rlp.decode(Buffer.from(keystore, 'hex'));
    const Crypto = rlp.decode(Ksv3[3]);
    const Cipherparams = rlp.decode(Crypto[4]);
    const Kdfparams = rlp.decode(Crypto[5]);

    return {
        id: Ksv3[0].toString('utf8'),
        version: parseInt(Ksv3[1].toString('hex'), 16),
        address: Ksv3[2].toString('utf8'),
        crypto: {
            cipher: Crypto[0].toString('utf8'),
            ciphertext: Crypto[1].toString('utf8'),
            kdf: Crypto[2].toString('utf8'),
            mac: Crypto[3].toString('utf8'),
            cipherparams: {
                iv: Cipherparams[0].toString('utf8')
            },
            kdfparams: {
                dklen: parseInt(Kdfparams[1].toString('hex'), 16),
                n: parseInt(Kdfparams[2].toString('hex'), 16),
                p: parseInt(Kdfparams[3].toString('hex'), 16),
                r: parseInt(Kdfparams[4].toString('hex'), 16),
                salt: Kdfparams[5].toString('utf8')
            }
        }
    };
};


// Note: this is trying to follow closely the specs on
// http://web3js.readthedocs.io/en/1.0/web3-eth-accounts.html

function Wallet(accounts) {
    this._accounts = accounts;
    this.length = 0;
    this.defaultKeyName = "web3js_wallet";
}

Wallet.prototype._findSafeIndex = function (pointer) {
    pointer = pointer || 0;
    if (_.has(this, pointer)) {
        return this._findSafeIndex(pointer + 1);
    } else {
        return pointer;
    }
};

Wallet.prototype._currentIndexes = function () {
    const keys = Object.keys(this);
    const indexes = keys
        .map(function(key) { return parseInt(key); })
        .filter(function(n) { return (n < 9e20); });

    return indexes;
};

Wallet.prototype.create = function (numberOfAccounts, entropy) {
    for (let i = 0; i < numberOfAccounts; ++i) {
        this.add(this._accounts.create(entropy).privateKey);
    }
    return this;
};

Wallet.prototype.add = function (account) {

    if (_.isString(account)) {
        account = this._accounts.privateKeyToAccount(account);
    }
    if (!this[account.address]) {
        account = this._accounts.privateKeyToAccount(account.privateKey);
        account.index = this._findSafeIndex();

        this[account.index] = account;
        this[account.address] = account;
        this[account.address.toLowerCase()] = account;

        this.length++;

        return account;
    } else {
        return this[account.address];
    }
};

Wallet.prototype.remove = function (addressOrIndex) {
    const account = this[addressOrIndex];

    if (account && account.address) {
        // address
        this[account.address].privateKey = null;
        delete this[account.address];
        // address lowercase
        this[account.address.toLowerCase()].privateKey = null;
        delete this[account.address.toLowerCase()];
        // index
        this[account.index].privateKey = null;
        delete this[account.index];

        this.length--;

        return true;
    } else {
        return false;
    }
};

Wallet.prototype.clear = function () {
    const _this = this;
    const indexes = this._currentIndexes();

    indexes.forEach(function(index) {
        _this.remove(index);
    });

    return this;
};

Wallet.prototype.encrypt = function (password, options) {
    const _this = this;
    const indexes = this._currentIndexes();

    const accounts = indexes.map(function(index) {
        return _this[index].encrypt(password, options);
    });

    return accounts;
};


Wallet.prototype.decrypt = function (encryptedWallet, password) {
    const _this = this;

    encryptedWallet.forEach(function (keystore) {
        const account = _this._accounts.decrypt(keystore, password);

        if (account) {
            _this.add(account);
        } else {
            throw new Error('Couldn\'t decrypt accounts. Password wrong?');
        }
    });

    return this;
};

Wallet.prototype.save = function (password, keyName) {
    localStorage.setItem(keyName || this.defaultKeyName, JSON.stringify(this.encrypt(password)));

    return true;
};

Wallet.prototype.load = function (password, keyName) {
    let keystore = localStorage.getItem(keyName || this.defaultKeyName);

    if (keystore) {
        try {
            keystore = JSON.parse(keystore);
        } catch(e) {

        }
    }

    return this.decrypt(keystore || [], password);
};

if (typeof localStorage === 'undefined') {
    delete Wallet.prototype.save;
    delete Wallet.prototype.load;
}

module.exports = Accounts;
