const crypto = require("crypto");

const encryptPassword = (password, PubKey, keyId) => {
  const randKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const rsaEncrypted = crypto.publicEncrypt(
    {
      key: Buffer.from(PubKey, "base64").toString(),
      padding: crypto.constants.RSA_PKCS1_PADDING
    },
    randKey
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", randKey, iv);
  const time = Math.floor(Date.now() / 1000).toString();
  cipher.setAAD(Buffer.from(time));
  const aesEncrypted = Buffer.concat([
    cipher.update(password, "utf8"),
    cipher.final()
  ]);
  const sizeBuffer = Buffer.alloc(2, 0);
  sizeBuffer.writeInt16LE(rsaEncrypted.byteLength, 0);
  const authTag = cipher.getAuthTag();
  const encrypted = Buffer.concat([
    Buffer.from([1, keyId]),
    iv,
    sizeBuffer,
    rsaEncrypted,
    authTag,
    aesEncrypted
  ]).toString("base64");
  return ["#PWD_INSTAGRAM", "4", time, encrypted].join(":");
};
module.exports = encryptPassword;
