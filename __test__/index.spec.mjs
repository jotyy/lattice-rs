import test from "ava";

import { decryptFilekey, encryptFilekey } from "../index.js";

test("decrypt filekey correct", (t) => {
  const filekey = {
    uuid: "c29bfe34-79c3-4e77-a560-d70adf31e264",
    address: "zltc_if4hw516jzyssfKJYcmnqPrt2u7m9Fm7X",
    cipher: {
      aes: {
        cipher: "aes-128-ctr",
        cipherText:
          "b30d8f76dba49df976755b933192f7ad066b57eb754ddbee3a097d6c7ea3960b",
        iv: "43a4646a3bfae2ba921644326f0f70c5",
      },
      kdf: {
        kdf: "scrypt",
        kdfParams: {
          DKLen: 32,
          n: 262144,
          p: 1,
          r: 8,
          salt: "530d12b5614a3d3430164700a8dde38e036d1acfcf1fb9b48b209fd8b3ddcf6c",
        },
      },
      cipherText:
        "b30d8f76dba49df976755b933192f7ad066b57eb754ddbee3a097d6c7ea3960b",
      mac: "28071ccac22c4f34e7043463f407baf581c5ad2317ca9b4bd80631113bc65b93",
    },
    isGM: true,
  };
  const password = "Aa123456";
  t.is(
    decryptFilekey(JSON.stringify(filekey), password).privateKey,
    "642400b95187ba1233444b3414fb9d7d676279ce458de5e67d0265753df75e7d"
  );
});

test("encrypt filekey correct", (t) => {
  const filekey = {
    uuid: "c29bfe34-79c3-4e77-a560-d70adf31e264",
    address: "zltc_if4hw516jzyssfKJYcmnqPrt2u7m9Fm7X",
    cipher: {
      aes: {
        cipher: "aes-128-ctr",
        cipherText:
          "b30d8f76dba49df976755b933192f7ad066b57eb754ddbee3a097d6c7ea3960b",
        iv: "43a4646a3bfae2ba921644326f0f70c5",
      },
      kdf: {
        kdf: "scrypt",
        kdfParams: {
          DKLen: 32,
          n: 262144,
          p: 1,
          r: 8,
          salt: "530d12b5614a3d3430164700a8dde38e036d1acfcf1fb9b48b209fd8b3ddcf6c",
        },
      },
      cipherText:
        "b30d8f76dba49df976755b933192f7ad066b57eb754ddbee3a097d6c7ea3960b",
      mac: "28071ccac22c4f34e7043463f407baf581c5ad2317ca9b4bd80631113bc65b93",
    },
    isGM: true,
  };
  const privateKey =
    "642400b95187ba1233444b3414fb9d7d676279ce458de5e67d0265753df75e7d";
  const password = "Aa123456";
  t.is(
    JSON.parse(encryptFilekey(privateKey, password, true)).address,
    filekey.address
  );
});

test("encrypt nist filekey correct", (t) => {
  const privateKey =
    "cb1195d51d66f4c2cc5c863477fc3d26c2731de869a870fcef38da253615ef8d";
  const password = "asdf1234";
  t.is(
    JSON.parse(encryptFilekey(privateKey, password, false)).address,
    "zltc_WE7PFWmp3atUhk2t8K96jijz89uFcSwjp"
  );
});

test("decrypt nist filekey", (t) => {
  const filekey = {
    uuid: "c7bd33b8-a520-41d9-a0b3-d56ea3980dbc",
    address: "zltc_my9gyz31TQkGTutVvwfSpdeNZecyjHWpT",
    cipher: {
      aes: {
        cipher: "aes-128-ctr",
        iv: "2f9eaeb8f28c51d8d3f84e5c025dc6fb",
      },
      kdf: {
        kdf: "scrypt",
        kdfParams: {
          DKLen: 32,
          n: 262144,
          p: 1,
          r: 8,
          salt: "0e916e0dfaf9c164690952056f30e29148b81c59f184a305059d6931f3120acc",
        },
      },
      cipherText:
        "19a93745eb44a5355e415d550af0ebf43cbb43c70a8ad1ed6bac7ecd5ae03c4e",
      mac: "01eca651a5304c9b9f410c1bd968c9f6687a64f6e5b944f0387283462be02f7b",
    },
    isGM: false,
  };
  const privateKey =
    "aea7ea1dd38b28d114c24f6a43a9c8d2525f701f509f24148d9d52b75c70139b";

  const password = "1234qwer";

  t.is(
    decryptFilekey(JSON.stringify(filekey), password).privateKey,
    privateKey
  );
});
