const { hashify, matchify } = require('../index');

const TEST_PASSWORD = 'yeAreTheS4ltOfThe3ArTh';
const BAD_TEST_PASSWORD = 'ifTheS4ltH4thL0stItsSavor';

const CUSTOM_SALT = 'loveYourEnemies';
const CUSTOM_ITERATIONS = 70 * 7;
const CUSTOM_KEY_LENGTH = 32;
const CUSTOM_DIGEST = 'sha256';
const CUSTOM_ENCODING = 'UTF-8';

test('To succeed after storing and comparing a matching password', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, salt, iterations, TEST_PASSWORD);
  expect(pass).toBe(true);
});

test('To fail after storing and comparing a non-matching password', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, salt, iterations, BAD_TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To generate random salts if no salt is provided', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const { salt: salt2, hash: hash2, iterations: iterations2 } = await hashify(TEST_PASSWORD);
  const pass1 = await matchify(hash, salt, iterations, TEST_PASSWORD);
  expect(pass1).toBe(true);
  const pass2 = await matchify(hash2, salt2, iterations2, TEST_PASSWORD);
  expect(pass2).toBe(true);
  expect(salt).not.toBe(salt2);
});

test('To use custom salt (hashify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD, CUSTOM_SALT);
  const pass = await matchify(hash, 'different-salt', iterations, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom salt (matchify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, CUSTOM_SALT, iterations, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom iterations (hashify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD, undefined, CUSTOM_ITERATIONS);
  const pass = await matchify(hash, 'different-salt', undefined, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom iterations (matchify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, salt, CUSTOM_ITERATIONS, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom key length (hashify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD, undefined, undefined, CUSTOM_ITERATIONS);
  const pass = await matchify(hash, 'different-salt', iterations, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom key length (matchify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, salt, CUSTOM_ITERATIONS, TEST_PASSWORD, CUSTOM_KEY_LENGTH);
  expect(pass).toBe(false);
});

test('To use custom digest (hashify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD, undefined, undefined, undefined, CUSTOM_DIGEST);
  const pass = await matchify(hash, 'different-salt', iterations, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom digest (matchify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, salt, CUSTOM_ITERATIONS, TEST_PASSWORD, undefined, CUSTOM_DIGEST);
  expect(pass).toBe(false);
});

test('To use custom encoding (hashify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD, undefined, undefined, undefined, undefined, CUSTOM_ENCODING);
  const pass = await matchify(hash, 'different-salt', iterations, TEST_PASSWORD);
  expect(pass).toBe(false);
});

test('To use custom encoding (matchify)', async () => {
  const { salt, hash, iterations } = await hashify(TEST_PASSWORD);
  const pass = await matchify(hash, salt, CUSTOM_ITERATIONS, TEST_PASSWORD, undefined, undefined, CUSTOM_ENCODING);
  expect(pass).toBe(false);
});
