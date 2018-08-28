# aion-keystore

This package is derived from a unreleased version of ``aion-web3 1.0``. The features here were tested to be functioning correctly. Subsequently, this package is expected to be ``deprecated`` when ``aion-web3 1.0`` releases. At which point it will be come unsupported, and users should migrate.

The functionality that this package provides are:

* Signing transactions (client side)
* Deriving Account information (``publicKey``, ``address``)
* Import ``Aion`` keystore from RLP encoded ``Buffer``s
* Export ``Aion`` keystore to RLP encoded ``Buffer``s

## Installation

### Node.js

```bash
npm install aion-keystore
```

## Usage

### Basics
~~~~js
// in node.js
const Accounts = require('aion-keystore');

const account = new Accounts();
const acc = account.create();

// output
acc = {
  _privateKey: Buffer,
  _publicKey: Buffer,
  privateKey: '0xce48884694409e26535e1a6e4e9d21747acdf2d59be910397af31f42de6fd1241ca54b71d7567a0eb6949031eeb3948f9ad7dc6f0689cdbccfff1b7cfc2b9139',
  publicKey: '0x1ca54b71d7567a0eb6949031eeb3948f9ad7dc6f0689cdbccfff1b7cfc2b9139',
  address: '0xa0a3b5b5fc4957cdd15aaec7ec7c968b81e617ca8ad763a2ca7494a6a70ac6e3',
  signTransaction: function(),
  sign: function(),
  encrypt: function(),
  encryptToRlp: function() 
};

~~~~

### Signing Transactions (Promise)

~~~~js
// in node.js
const privateKey = "0xefbc7a4bb0bf24624f97409473027b62f7ff76e3d232f167e002e1f5872cc2884dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee";
const accs = new Accounts();

// load account from private key
const acc = accs.privateKeyToAccount(privateKey);

// construct transaction payload
const transaction = {
  to: "0xa050486fc4a5c236a9072961a5b7394885443cd53a704b2630d495d2fc6c268b",
  data: "",
  gasPrice: 10000000000,
  gas: 21000,
  value: new BN("1000000000000000000"),
  nonce: 1,
  timestamp: 1535399697
};

acc.signTransaction(transaction)
.then((signed) => {
  console.log(signed);
  // outputs
  {
    messageHash: '0xfa466752c7a073d6bfd745d89f811a803e2d0654c74230ab01e656eb52fd4369',
    signature: '0x4dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee84be4c9fdfa713e23c6b1b7f74e77f2a65037b82088611ae496c40ffc182fce2683787da136b19872cc7d9ac95a1c3400e2345202a7b09ec67c876587818010b',
    rawTransaction: '0xf8a001a0a050486fc4a5c236a9072961a5b7394885443cd53a704b2630d495d2fc6c268b880de0b6b3a764000080845b8457118252088800000002540be40001b8604dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee84be4c9fdfa713e23c6b1b7f74e77f2a65037b82088611ae496c40ffc182fce2683787da136b19872cc7d9ac95a1c3400e2345202a7b09ec67c876587818010b'
  };
}).catch((err) => {
  console.log(err);
});
~~~~

### Signing Transactions (Callback)

~~~~js
// in node.js
const privateKey = "0xefbc7a4bb0bf24624f97409473027b62f7ff76e3d232f167e002e1f5872cc2884dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee";
const accs = new Accounts();

// load account from private key
const acc = accs.privateKeyToAccount(privateKey);

// construct transaction payload
const transaction = {
  to: "0xa050486fc4a5c236a9072961a5b7394885443cd53a704b2630d495d2fc6c268b",
  data: "",
  gasPrice: 10000000000,
  gas: 21000,
  value: new BN("1000000000000000000"),
  nonce: 1,
  timestamp: 1535399697
};

acc.signTransaction(transaction, (err, res) => {
  if (err) {
    console.log(err);
    return;
  }

  console.log(res);
  // outputs same as above (promise example)
});
~~~~