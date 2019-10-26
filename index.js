const crypto = require('crypto');
const pbkdf2 = require('util').promisify(crypto.pbkdf2);

module.exports = { hashify, matchify };

const randomSalt = () => crypto.randomBytes(128).toString('base64');
const DEFAULT_ITERATIONS = 10000;
const DEFAULT_KEY_LEN = 64;
const DEFAULT_DIGEST = 'sha512';
const DEFAULT_ENCODING = 'hex';

/**
 * Hash a password.
 * @param {string} password Password
 * @param {string} [salt=randomSalt()] Salt
 * @param {number} [iterations=1000] Iterations
 * @param {number} [keyLen=64] Key length
 * @param {string} [digest='sha512'] Digest
 * @param {string} [encoding='hex'] Encoding
 * @return {object} Hash object (e.g. { salt, hash, iterations })
 */
async function hashify (password, salt = randomSalt(), iterations = DEFAULT_ITERATIONS, keyLen = DEFAULT_KEY_LEN, digest = DEFAULT_DIGEST, encoding = DEFAULT_ENCODING) {
  const derivedKey = await pbkdf2(password, salt, iterations, keyLen, digest);
  const hash = derivedKey.toString(encoding);
  return { salt, hash, iterations };
}

/**
 * Report whether a hash matches a password.
 * @param {string} hash Saved hash
 * @param {string} salt Saved salt
 * @param {string} [iterations=1000] Iterations
 * @param {string} [salt=randomSalt()] Salt
 * @param {number} [iterations=1000] Iterations
 * @param {string} potentialPassword Password attempt
 * @param {number} [keyLen=64] Key length
 * @param {string} [digest='sha512'] Digest
 * @param {string} [encoding='hex'] Encoding
 * @return {boolean} Whether the hash + salt + iterations matched the attempted
 * password
 */
async function matchify (hash, salt, iterations = DEFAULT_ITERATIONS, potentialPassword, keyLen = DEFAULT_KEY_LEN, digest = DEFAULT_DIGEST, encoding = DEFAULT_ENCODING) {
  const derivedKey = await pbkdf2(potentialPassword, salt, iterations, keyLen, digest);
  return hash === derivedKey.toString(encoding);
}
