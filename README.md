# web3-eth-accounts

This package is derived from a unreleased version of ``aion-web3 1.0``. The features here were tested to be functioning correctly. Subsequently, this package is expected to be ``deprecated`` when ``aion-web3 1.0`` releases. At which point it will be come unsupported, and users should migrate.

The functionality that this package provides are:

* Signing transactions (client side)
* Deriving Account information (``publicKey``, ``address``)
* Import ``Aion`` keystore files
* Export ``Aion`` keystore files

## Installation

### Node.js

```bash
npm install aion-keystore
```

## Usage

```js
// in node.js
const Web3EthAccounts = require('aion-keystore');

const account = new Web3EthAccounts('ws://localhost:8546');
account.create();
> {
  address: '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23',
  privateKey: '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  signTransaction: function(tx){...},
  sign: function(data){...},
  encrypt: function(password){...}
}
```

[docs]: http://web3js.readthedocs.io/en/1.0/
[repo]: https://github.com/ethereum/web3.js