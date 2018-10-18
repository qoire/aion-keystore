/// Basic Account Functionality Tests
const assert = require('chai').assert;
const Accounts = require('../src/index');
const BN = require('bn.js');
const { removeLeadingZeroX } = require('../src/accounts-format');

describe("basic account tests", () => {
  describe("account private/public key tests", () => {
    it("should correctly add an account", () => {
      const accs = new Accounts();
      const acc = accs.create();
      assert.isNotNull(acc.publicKey);
      assert.isNotNull(acc.address);
    });

    it("should generate an account", () => {
      // information retrieved from AION node
      const expectedAddress = "0xa0359946e3d0cc409e4079608f4efb7fd19a93f23a968c9130270f36af92141c";
      const privateKey = "0xefbc7a4bb0bf24624f97409473027b62f7ff76e3d232f167e002e1f5872cc2884dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee";

      const accs = new Accounts();
      const acc = accs.privateKeyToAccount(privateKey);
      assert.equal(acc.address, expectedAddress);
    });

    it("should generate a valid signature", async () => {
      const privateKey = "0xefbc7a4bb0bf24624f97409473027b62f7ff76e3d232f167e002e1f5872cc2884dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee";
      const expectedEncodedTransaction = "0xf8a001a0a050486fc4a5c236a9072961a5b7394885443cd53a704b2630d495d2fc6c268b880de0b6b3a764000080845b8457118252088800000002540be40001b8604dcff097bf9912b71d619fc78100de8cf7f55dfddbc2bf5f9fdc36bd670781ee84be4c9fdfa713e23c6b1b7f74e77f2a65037b82088611ae496c40ffc182fce2683787da136b19872cc7d9ac95a1c3400e2345202a7b09ec67c876587818010b";

      const accs = new Accounts();
      const acc = accs.privateKeyToAccount(privateKey);

      const transaction = {
        to: "0xa050486fc4a5c236a9072961a5b7394885443cd53a704b2630d495d2fc6c268b",
        data: "",
        gasPrice: 10000000000,
        gas: 21000,
        value: new BN("1000000000000000000"),
        nonce: 1,
        timestamp: 1535399697
      };

      // we should get the same results using callback and promise API
      const res = await acc.signTransaction(transaction);
      assert.equal(res.rawTransaction, expectedEncodedTransaction);
    });
  });

  describe("should properly import and export from keystore files", () => {
    const keystores = require('./ksv3_test_vector.json');

    it("should correctly import ksv3 keystore files", () => {
      const accs = new Accounts();
      const rmzx = removeLeadingZeroX;

      // no need to run the whole thing
      for (let i = 0; i < 1; i++) {
        const k = keystores[i];
        const acc = accs.decryptFromRlp(Buffer.from(k.ksv3, 'hex'), k.password);
        assert.equal(rmzx(acc.address), k.address);
        assert.equal(rmzx(acc.privateKey.toString('hex')), k.privateKey);
        assert.equal(rmzx(acc.publicKey.toString('hex')), k.publicKey);
      }
    }).timeout(5000);

    it("should parse import from ksv3, reserialize and get same encoding", () => {
      const accs = new Accounts();

      // no need to run the whole thing
      const accounts = [];
      for (let i = 0; i < 1; i++) {
        const k = keystores[i];
        const acc = accs.decryptFromRlp(Buffer.from(k.ksv3, 'hex'), k.password);

        // tag on test fields for later use
        acc.test_password = k.password;
        acc.test_ksv3 = k.ksv3;
        acc.test_salt = Buffer.from(k.salt, 'hex');
        acc.test_iv = Buffer.from(k.iv, 'hex');
        acc.test_uuid = k.uuid;
        accounts.push(acc);
      }

      for (let i = 0; i < accounts.length; i++) {
        const a = accounts[i];
        const encoded = a.encryptToRlp(a.test_password, { salt: a.test_salt, iv: a.test_iv, uuid: a.test_uuid });
        assert.equal(encoded.toString('hex'), a.test_ksv3);
      }
    }).timeout(5000);
  });

  describe("should properly sign arbitrary messages in different fashions", () => {
    it("should sign a message in a fashion that can be recovered (AION compliant)", () => {
      const accs = new Accounts();
      const acc = accs.create();

      const inputMsg = "hello world!";
      const out = acc.sign(inputMsg);

      const outputAddress = acc.recover(inputMsg, out.signature);
      assert.equal(outputAddress, acc.address);
    });

    it("should fail when signature is incorrect (AION compliant)", () => {
      const accs = new Accounts();
      const acc = accs.create();

      const inputMsg = "good day sir!";

      const wrongInputMsg = "good day to you too!";
      const wrongSignature = acc.sign(wrongInputMsg);

      let caughtError = false;
      try {
        const outputAddress = acc.recover(inputMsg, wrongSignature);
      } catch (e) {
        // do nothing, this is expected case
        caughtError = true;
      }

      assert.equal(caughtError, true);
    });

    it("should sign a message in a fashion that can be recovered", () => {
      const accs = new Accounts();
      const acc = accs.create();

      const inputMsg = "hello world!";
      const out = acc.signMessage(inputMsg);

      const outputAddress = acc.recoverMessage(inputMsg, out.signature);
      assert.equal(outputAddress, acc.address);
    });

    it("should fail when signature is incorrect", () => {
      const accs = new Accounts();
      const acc = accs.create();

      const inputMsg = "good day sir!";

      const wrongInputMsg = "good day to you too!";
      const wrongSignature = acc.signMessage(wrongInputMsg);

      let caughtError = false;
      try {
        const outputAddress = acc.recoverMessage(inputMsg, wrongSignature);
      } catch (e) {
        // do nothing, this is expected case
        caughtError = true;
      }

      assert.equal(caughtError, true);
    });
  });
});