const crypto = require('crypto')
const { ENCRYPTION_METHOD } = require('./defaults')

function generateKeyFromPassword(password) {
  const keyLength = 32
  const iterations = 100000;
  return crypto.pbkdf2Sync(password, '', iterations, keyLength, 'sha256');
}

const decrypt = (data, password) => {
  const keyBuffer = generateKeyFromPassword(password);
  const ivBuffer = data.slice(0, 16);
  const encryptedData = data.slice(16); // Извлекаем зашифрованные данные, исключая IV
  const decipher = crypto.createDecipheriv(ENCRYPTION_METHOD, keyBuffer, ivBuffer);
  const chunk1 = decipher.update(encryptedData);
  const chunk2 = decipher.final();
  return Buffer.concat([chunk1, chunk2], chunk1.length + chunk2.length);
}

const encrypt = (message, password) => {
  const keyBuffer = generateKeyFromPassword(password);
  const ivBuffer = crypto.randomBytes(16); // Генерация уникального IV
  const cipher = crypto.createCipheriv(ENCRYPTION_METHOD, keyBuffer, ivBuffer);
  const chunk1 = cipher.update(message);
  const chunk2 = cipher.final();
  return Buffer.concat([ivBuffer, chunk1, chunk2], ivBuffer.length + chunk1.length + chunk2.length);
}

const getShasumData = message =>
  crypto
    .createHash('sha256')
    .update(message)
    .digest()

module.exports = {
  decrypt,
  encrypt,
  getShasumData,
}
