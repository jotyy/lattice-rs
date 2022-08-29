import test from "ava";

import { decryptFilekey } from "../index.js";

test("parse filekey correct", (t) => {
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
  };
  const password = "Aa123456";
  t.is(
    decryptFilekey(JSON.stringify(filekey), password).sk,
    "642400b95187ba1233444b3414fb9d7d676279ce458de5e67d0265753df75e7d"
  );
});
