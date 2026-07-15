// Copyright 2022 Roy T. Hashimoto. All Rights Reserved.
// VENDORED from @vlcn.io/wa-sqlite/src/examples/IDBContext.js.
// Change from upstream: the ObjectStore wrapper transparently encrypts the
// `data` field of every block record on the way INTO IndexedDB and decrypts it
// on the way OUT (xchacha20poly1305, per-record nonce). SQLite thus always sees
// plaintext pages in memory, while only ciphertext pages hit disk.
//
// WHY noble (not WebCrypto) here, uniquely in this codebase: page encryption
// MUST be SYNCHRONOUS. wa-sqlite's VFS issues `blocks.put()` fire-and-forget
// inside a synchronous IndexedDB transaction callback; awaiting WebCrypto (which
// is async) between opening the transaction and issuing the put would let the
// IDB transaction auto-commit → "transaction inactive". WebCrypto has no sync
// API, so this one spot keeps a sync cipher. All other crypto is WebCrypto.
//
// Gated on `data instanceof Uint8Array`, so the purge/metadata block (whose
// `data` is a Map) passes through untouched. Structural fields
// (path/offset/version/fileSize) stay cleartext — they are the store's keyPath.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

// IndexedDB transactions older than this will be replaced.
const MAX_TRANSACTION_LIFETIME_MILLIS = 5_000;

// ---- per-block page encryption (SYNC — see note above) ------------------
const encryptBlock = (value, key) => {
  if (!key || !(value?.data instanceof Uint8Array)) return value;
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const ct = xchacha20poly1305(key, nonce).encrypt(value.data);
  return { ...value, data: ct, _n: nonce, _e: 1 };
};
const decryptBlock = (value, key) => {
  if (!key || !value || value._e !== 1) return value;
  const pt = xchacha20poly1305(key, value._n).decrypt(value.data);
  const out = { ...value, data: pt };
  delete out._n; delete out._e;
  return out;
};

// For debugging.
let nextTxId = 0;
const mapTxToId = new WeakMap();
function log(...args) {
  // console.debug(...args);
}

// This class manages IDBTransaction and IDBRequest instances. It tries
// to reuse transactions to minimize transaction overhead.
export class EncryptingIDBContext {
  /** @type {IDBDatabase} */ #db;
  /** @type {Promise<IDBDatabase>} */ #dbReady;
  #txOptions;
  /** @type {Uint8Array|null} */ #key;

  /** @type {IDBTransaction} */ #tx = null;
  #txTimestamp = 0;
  #runChain = Promise.resolve();
  #putChain = Promise.resolve();

  /**
   * @param {IDBDatabase|Promise<IDBDatabase>} idbDatabase
   * @param {object} txOptions
   * @param {Uint8Array|null} key 32-byte page-encryption key, or null for none
   */
  constructor(idbDatabase, txOptions = { durability: 'default' }, key = null) {
    this.#dbReady = Promise.resolve(idbDatabase).then(db => this.#db = db);
    this.#txOptions = txOptions;
    this.#key = key ?? null;
  }

  async close() {
    const db = this.#db ?? await this.#dbReady;
    await this.#runChain;
    await this.sync();
    db.close();
  }
  
  /**
   * Run a function with the provided object stores. The function
   * should be idempotent in case it is passed an expired transaction.
   * @param {IDBTransactionMode} mode
   * @param {(stores: Object.<string, ObjectStore>) => any} f 
   */
  async run(mode, f) {
    // Ensure that functions run sequentially.
    const result = this.#runChain.then(() => this.#run(mode, f));
    this.#runChain = result.catch(() => {});
    return result;
  }

  /**
   * @param {IDBTransactionMode} mode
   * @param {(stores: Object.<string, ObjectStore>) => any} f 
   * @returns 
   */
  async #run(mode, f) {
    const db = this.#db ?? await this.#dbReady;
    if (mode === 'readwrite' && this.#tx?.mode === 'readonly') {
      // Mode requires a new transaction.
      this.#tx = null;
    } else if (performance.now() - this.#txTimestamp > MAX_TRANSACTION_LIFETIME_MILLIS) {
      // Chrome times out transactions after 60 seconds so refresh preemptively.
      try {
        this.#tx?.commit();
      } catch (e) {
        // Explicit commit can fail but this can be ignored if it will
        // auto-commit anyway.
        if (e.name !== 'InvalidStateError') throw e;
      }

      // Skip to the next task to allow processing.
      await new Promise(resolve => setTimeout(resolve));
      this.#tx = null;
    }

    // Run the user function with a retry in case the transaction is invalid.
    for (let i = 0; i < 2; ++i) {
      if (!this.#tx) {
        // @ts-ignore
        this.#tx = db.transaction(db.objectStoreNames, mode, this.#txOptions);
        const timestamp = this.#txTimestamp = performance.now();

        // Chain the result of every transaction. If any transaction is
        // aborted then the next sync() call will throw.
        this.#putChain = this.#putChain.then(() => {
          return new Promise((resolve, reject) => {
            this.#tx.addEventListener('complete', event => {
              resolve();
              if (this.#tx === event.target) {
                this.#tx = null;
              }
              log(`transaction ${mapTxToId.get(event.target)} complete`);
            });
            this.#tx.addEventListener('abort', event => {
              console.warn('tx abort', (performance.now() - timestamp)/1000);
              // @ts-ignore
              const e = event.target.error;
              reject(e);
              if (this.#tx === event.target) {
                this.#tx = null;
              }
              log(`transaction ${mapTxToId.get(event.target)} aborted`, e);
            });
          });
        });

        log(`new transaction ${nextTxId} ${mode}`);
        mapTxToId.set(this.#tx, nextTxId++);
      }

      try {
        const stores = Object.fromEntries(Array.from(db.objectStoreNames, name => {
          return [name, new ObjectStore(this.#tx.objectStore(name), this.#key)];
        }));
        return await f(stores);
      } catch (e) {
        this.#tx = null;
        if (i) throw e;
        // console.warn('retrying with new transaction');
      }
    }
  }

  async sync() {
    // Wait until all transactions since the previous sync have committed.
    // Throw if any transaction failed.
    await this.#runChain;
    await this.#putChain;
    this.#putChain = Promise.resolve();
  }
}

/**
 * Helper to convert IDBRequest to Promise.
 * @param {IDBRequest} request 
 * @returns {Promise}
 */
function wrapRequest(request) {
  return new Promise((resolve, reject) => {
    request.addEventListener('success', () => resolve(request.result));
    request.addEventListener('error', () => reject(request.error));
  });
}

// IDBObjectStore wrapper passed to IDBContext run functions.
class ObjectStore {
  #objectStore;
  #key;

  /**
   * @param {IDBObjectStore} objectStore
   * @param {Uint8Array|null} key
   */
  constructor(objectStore, key = null) {
    this.#objectStore = objectStore;
    this.#key = key;
  }

  /**
   * @param {IDBValidKey|IDBKeyRange} query
   * @returns {Promise}
   */
  async get(query) {
    log(`get ${this.#objectStore.name}`, query);
    const record = await wrapRequest(this.#objectStore.get(query));
    return decryptBlock(record, this.#key);
  }

  /**
   * @param {IDBValidKey|IDBKeyRange} query
   * @param {number} [count]
   * @returns {Promise}
   */
   async getAll(query, count) {
    log(`getAll ${this.#objectStore.name}`, query, count);
    const records = await wrapRequest(this.#objectStore.getAll(query, count));
    return Array.isArray(records) ? records.map(r => decryptBlock(r, this.#key)) : records;
  }

  /**
   * @param {IDBValidKey|IDBKeyRange} query 
   * @returns {Promise<IDBValidKey>}
   */
  getKey(query) {
    log(`getKey ${this.#objectStore.name}`, query);
    const request = this.#objectStore.getKey(query);
    return wrapRequest(request);
  }

  /**
   * @param {IDBValidKey|IDBKeyRange} query 
   * @param {number} [count]
   * @returns {Promise}
   */
   getAllKeys(query, count) {
    log(`getAllKeys ${this.#objectStore.name}`, query, count);
    const request = this.#objectStore.getAllKeys(query, count);
    return wrapRequest(request);
  }

  /**
   * @param {any} value
   * @param {IDBValidKey} [key] 
   * @returns {Promise}
   */
   put(value, key) {
    log(`put ${this.#objectStore.name}`, value, key);
    const request = this.#objectStore.put(encryptBlock(value, this.#key), key);
    return wrapRequest(request);
  }

  /**
   * @param {IDBValidKey|IDBKeyRange} query 
   * @returns {Promise}
   */
   delete(query) {
    log(`delete ${this.#objectStore.name}`, query);
    const request = this.#objectStore.delete(query);
    return wrapRequest(request);
  }

  clear() {
    log(`clear ${this.#objectStore.name}`);
    const request = this.#objectStore.clear();
    return wrapRequest(request);
  }

  index(name) {
    return new Index(this.#objectStore.index(name));
  }
}

class Index {
  /** @type {IDBIndex} */ #index;

  /**
   * @param {IDBIndex} index 
   */
   constructor(index) {
    this.#index = index;
  }

  /**
   * @param {IDBValidKey|IDBKeyRange} query 
   * @param {number} [count]
   * @returns {Promise<IDBValidKey[]>}
   */
  getAllKeys(query, count) {
    log(`IDBIndex.getAllKeys ${this.#index.objectStore.name}<${this.#index.name}>`, query, count);
    const request = this.#index.getAllKeys(query, count);
    return wrapRequest(request);
  }
}