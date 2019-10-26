# hashify-matchify
Salt and hash passwords using [crypto](https://nodejs.org/api/crypto.html#crypto_crypto_pbkdf2_password_salt_iterations_keylen_digest_callback)
## Install
`$ npm i --save hashify-matchify`  
```js
const { hashify, matchify } = require('hashify-matchify');
```
## Hash
```js
// by default a random salt is used, but a salt may be provided as the 2nd param
const { salt, hash, iterations } = await hashify('password');
```
## Check
```js
const pass = await matchify(hash, salt, iterations, 'password');
```
