/**
 * accounts-format.js, common patterns for accounts
 *
 * This is ported over from a currently unreleased version of aion-web3 1.0. For more information see:
 * https://github.com/aionnetwork/aion_web3/issues/10
 */

let randomHex = require('randomhex');
const numberToBN = require('number-to-bn');

let {
  isEmpty,
  isArray,
  isString,
  isNumber,
  isNull,
  isUndefined
} = require('underscore');

let BN = require('bn.js');
let patterns = require('./accounts-pattern');

const { blake2b256Hex } = require('./accounts-crypto');

let copyString = val => '' + val

// static constants, most ported from values
const values = {
  zeroX: '0x',
  hex: {
    randomHexSize: 32
  }
};

/**
 * True if string starts with '0x'
 * @param {string} val
 * @return {boolean}
 */
let startsWithZeroX = val =>
  isString(val) === true && patterns.zeroX.test(val) === true

/**
 * Removes '0x' from a string
 * @param {string} val
 * @return {string} checkAddressChecksum
 */
let removeLeadingZeroX = val =>
  startsWithZeroX(val) === true ? val.replace(patterns.zeroX, '') : val

/**
 * Put the 0x at the beginning of a string
 * @param {string} val
 * @return {string}
 */
let prependZeroX = val =>
  startsWithZeroX(val) === false ? values.zeroX + val : val

/**
 * Strips '0x' and turns it into a Buffer
 * @param {string} val
 * @return {buffer}
 */
let hexToBuffer = val => toBuffer(val)

let bufferToHex = val => val.toString('hex')

let bufferToZeroXHex = val => prependZeroX(bufferToHex(val))

/**
 * Random Buffer of a size
 * @param {number} size
 * @return {buffer}
 */
let randomHexBuffer = (size = values.hex.randomHexSize) => {
  const rhex = removeLeadingZeroX(randomHex(size));
  return hexToBuffer(rhex);
}

/**
 * True if a string is hex
 * @param {string} val
 * @return {boolean}
 */
let isHex = val => isString(val) === true && patterns.hex.test(val) === true

/**
 * True if two buffers have the same length and bytes
 * @param {buffer} buf1
 * @param {buffer} buf2
 * @return {boolean}
 */
function equalBuffers(buf1, buf2) {
  if (buf1.length !== buf2.length) {
    return false
  }

  return buf1.every((byte, index) => {
    return buf2[index] === byte
  })
}

/**
 * Gracefully try to convert anything into a buffer
 * @param {object} val anything
 * @param {string} encoding hex, utf8
 * @return {buffer}
 */
function toBuffer(val, encoding) {
  if (val === undefined || val === null) {
    return Buffer.from([])
  }

  // buffer or array
  if (isArray(val) === true || Buffer.isBuffer(val) === true) {
    return Buffer.from(val)
  }

  if (isNaN(val) === false || isNumber(val) === true || BN.isBN(val) === true) {
    // to array from BN is an array of bytes
    return Buffer.from(numberToBN(val).toArray())
  }

  // string
  if (isString(val) === true && isEmpty(encoding) === true) {
    // hex
    if (isHex(val) === true) {
      return Buffer.from(removeLeadingZeroX(val), 'hex')
    }
  }

  // anything else
  return Buffer.from(val, encoding)
}

let isBuffer = val => Buffer.isBuffer(val)

function toNumber(val) {
  if (typeof val === 'number') {
    return val
  }

  if (isHex(val) === true) {
    return new BN(removeLeadingZeroX(val), 'hex').toNumber()
  }

  if (BN.isBN(val) === true) {
    return val.toNumber()
  }

  throw new Error(`unknown format "${typeof val}" ${val}`)
}

/// Following is ported from web3-utils in aion-web3 1.0

/**
 * Takes an input and transforms it into an BN
 *
 * @method toBN
 * @param {Number|String|BN} number, string, HEX string or BN
 * @return {BN} BN
 */
const toBN = (number) => {
    try {
        return numberToBN(number);
    } catch(e) {
        throw new Error(e + ' Given value: "'+ number +'"');
    }
};

/**
 * Check if string is HEX, requires a 0x in front
 *
 * @method isHexStrict
 * @param {String} hex to be checked
 * @returns {Boolean}
 */
const isHexStrict = (hex) => {
    return ((isString(hex) || isNumber(hex)) && /^(-)?0x[0-9a-f]*$/i.test(hex));
};

/**
 * Converts value to it's hex representation
 *
 * @method numberToHex
 * @param {String|Number|BN} value
 * @return {String}
 */
const numberToHex = (value) => {
    if (isNull(value) || isUndefined(value)) {
        return value;
    }

    if (!isFinite(value) && !isHexStrict(value)) {
        throw new Error('Given input "'+value+'" is not a number.');
    }

    const number = toBN(value);
    const result = number.toString(16);

    return number.lt(new BN(0)) ? '-0x' + result.substr(1) : '0x' + result;
};

/// Following is ported from web3-core-helpers in aion-web3 1.0

/**
 * Note: removed support for IBAN
 */
const inputAddressFormatter = (address) => {
    if (patterns.address.test(address)) {
        return '0x' + address.toLowerCase().replace('0x','');
    }
    throw new Error('Provided address "'+ address +'" is invalid');
};

/**
 * Formats the input of a transaction and converts all values to HEX
 *
 * @method _txInputFormatter
 * @param {Object} transaction options
 * @returns object
 */
const _txInputFormatter = (options) => {

    if (options.to) { // it might be contract creation
        options.to = inputAddressFormatter(options.to);
    }

    if (options.data && options.input) {
        throw new Error('You can\'t have "data" and "input" as properties of transactions at the same time, please use either "data" or "input" instead.');
    }

    if (!options.data && options.input) {
        options.data = options.input;
        delete options.input;
    }

    if(options.data && !isHex(options.data)) {
        throw new Error('The data field must be HEX encoded data.');
    }

    // allow both
    if (options.gas || options.gasLimit) {
        options.gas = options.gas || options.gasLimit;
    }

    ['gasPrice', 'gas', 'value', 'nonce'].filter(function (key) {
        return options[key] !== undefined;
    }).forEach(function(key){
        options[key] = numberToHex(options[key]);
    });

    return options;
};

/**
 * Formats the input of a transaction and converts all values to HEX
 * 
 * Note: modified to REMOVE from, in this context we don't need it
 * 
 * @method inputCallFormatter
 * @param {Object} transaction options
 * @returns object
*/
const inputCallFormatter = (options) => {
    options = _txInputFormatter(options);

    if (options.from) {
        options.from = inputAddressFormatter(from);
    }

    return options;
};

module.exports = {
  copyString,
  startsWithZeroX,
  removeLeadingZeroX,
  prependZeroX,
  hexToBuffer,
  bufferToHex,
  bufferToZeroXHex,
  randomHexBuffer,
  Buffer,
  equalBuffers,
  toBuffer,
  isBuffer,
  isHex,
  toNumber,
  inputCallFormatter,
  numberToHex,
  isHexStrict
};
