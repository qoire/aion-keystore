/**
 * accounts-crypto.js, crpyto utilities for accounts
 *
 * This is ported over from a currently unreleased version of aion-web3 1.0. For more information see:
 * https://github.com/aionnetwork/aion_web3/issues/10
 */

const blake2b = require('blake2b');
const k256 = require('js-sha3').keccak256;
const nacl = require('tweetnacl');
const scrypt = require('scryptsy');
const node = require('crypto');


const blake2b256 = (val) => {
  const out = Buffer.alloc(blake2b.BYTES);
  blake2b(blake2b.BYTES).update(val).digest(out);
  return out;
};

const keccak256 = (val) => {
  return k256(val);
};

/**
 * Hashes the value to a blake2b256 hash
 * To hash a HEX string the hex must have 0x in front.
 *
 * Note: modified to use Buffer.from(...) instead of hexToBytes
 *
 * @method blake2b256
 * @return {String} the blake2b256 string prepended with '0x'
 */
const blake2b256Hex = (value) => {
  if (isHexStrict(value) && /^0x/i.test((value).toString())) {
    value = Buffer.from(value.substr(2), 'hex');
  }
  const out = blake2b256(value);
  return aionLib.formats.prependZeroX(out.toString('hex'));
};

module.exports = {
  blake2b256,
  blake2b256Hex,
  nacl,
  scrypt,
  node,
  keccak256
};