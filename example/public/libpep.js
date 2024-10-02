let wasm;

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); }

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}
/**
* Generate a new global key pair
* @returns {GlobalKeyPair}
*/
export function makeGlobalKeys() {
    const ret = wasm.makeGlobalKeys();
    return GlobalKeyPair.__wrap(ret);
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}
/**
* Generate a subkey from a global secret key, a context, and an encryption secret
* @param {GlobalSecretKey} global
* @param {string} context
* @param {string} encryption_secret
* @returns {SessionKeyPair}
*/
export function makeSessionKeys(global, context, encryption_secret) {
    _assertClass(global, GlobalSecretKey);
    const ptr0 = passStringToWasm0(context, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(encryption_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.makeSessionKeys(global.__wbg_ptr, ptr0, len0, ptr1, len1);
    return SessionKeyPair.__wrap(ret);
}

/**
* Encrypt a pseudonym
* @param {Pseudonym} p
* @param {SessionPublicKey} pk
* @returns {EncryptedPseudonym}
*/
export function encryptPseudonym(p, pk) {
    _assertClass(p, Pseudonym);
    _assertClass(pk, SessionPublicKey);
    const ret = wasm.encryptData(p.__wbg_ptr, pk.__wbg_ptr);
    return EncryptedPseudonym.__wrap(ret);
}

/**
* Decrypt an encrypted pseudonym
* @param {EncryptedPseudonym} p
* @param {SessionSecretKey} sk
* @returns {Pseudonym}
*/
export function decryptPseudonym(p, sk) {
    _assertClass(p, EncryptedPseudonym);
    _assertClass(sk, SessionSecretKey);
    const ret = wasm.decryptData(p.__wbg_ptr, sk.__wbg_ptr);
    return Pseudonym.__wrap(ret);
}

/**
* Encrypt a data point
* @param {DataPoint} data
* @param {SessionPublicKey} pk
* @returns {EncryptedDataPoint}
*/
export function encryptData(data, pk) {
    _assertClass(data, DataPoint);
    _assertClass(pk, SessionPublicKey);
    const ret = wasm.encryptData(data.__wbg_ptr, pk.__wbg_ptr);
    return EncryptedDataPoint.__wrap(ret);
}

/**
* Decrypt an encrypted data point
* @param {EncryptedDataPoint} data
* @param {SessionSecretKey} sk
* @returns {DataPoint}
*/
export function decryptData(data, sk) {
    _assertClass(data, EncryptedDataPoint);
    _assertClass(sk, SessionSecretKey);
    const ret = wasm.decryptData(data.__wbg_ptr, sk.__wbg_ptr);
    return DataPoint.__wrap(ret);
}

/**
* Rerandomize the ciphertext of an encrypted pseudonym
* @param {EncryptedPseudonym} encrypted
* @returns {EncryptedPseudonym}
*/
export function rerandomizePseudonym(encrypted) {
    _assertClass(encrypted, EncryptedPseudonym);
    const ret = wasm.rerandomizeData(encrypted.__wbg_ptr);
    return EncryptedPseudonym.__wrap(ret);
}

/**
* Rerandomize the ciphertext of an encrypted data point
* @param {EncryptedDataPoint} encrypted
* @returns {EncryptedDataPoint}
*/
export function rerandomizeData(encrypted) {
    _assertClass(encrypted, EncryptedDataPoint);
    const ret = wasm.rerandomizeData(encrypted.__wbg_ptr);
    return EncryptedDataPoint.__wrap(ret);
}

/**
* Pseudonymize an encrypted pseudonym, from one context to another context
* @param {EncryptedPseudonym} p
* @param {string} from_user
* @param {string} to_user
* @param {string} from_session
* @param {string} to_session
* @param {string} pseudonymization_secret
* @param {string} encryption_secret
* @returns {EncryptedPseudonym}
*/
export function pseudonymize(p, from_user, to_user, from_session, to_session, pseudonymization_secret, encryption_secret) {
    _assertClass(p, EncryptedPseudonym);
    const ptr0 = passStringToWasm0(from_user, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(to_user, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(from_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(to_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(pseudonymization_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(encryption_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.pseudonymize(p.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
    return EncryptedPseudonym.__wrap(ret);
}

/**
* Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
* @param {EncryptedDataPoint} p
* @param {string} from_session
* @param {string} to_session
* @param {string} encryption_secret
* @returns {EncryptedDataPoint}
*/
export function rekeyData(p, from_session, to_session, encryption_secret) {
    _assertClass(p, EncryptedDataPoint);
    const ptr0 = passStringToWasm0(from_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(to_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(encryption_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.rekeyData(p.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
    return EncryptedDataPoint.__wrap(ret);
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    const mem = getDataViewMemory0();
    for (let i = 0; i < array.length; i++) {
        mem.setUint32(ptr + 4 * i, addHeapObject(array[i]), true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}
/**
* @param {GlobalSecretKey} global_secret_key
* @param {(BlindingFactor)[]} blinding_factors
* @returns {BlindedGlobalSecretKey}
*/
export function makeBlindedGlobalSecretKey(global_secret_key, blinding_factors) {
    _assertClass(global_secret_key, GlobalSecretKey);
    const ptr0 = passArrayJsValueToWasm0(blinding_factors, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.makeBlindedGlobalSecretKey(global_secret_key.__wbg_ptr, ptr0, len0);
    return BlindedGlobalSecretKey.__wrap(ret);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* @param {GroupElement} msg
* @param {GroupElement} public_key
* @returns {ElGamal}
*/
export function encrypt(msg, public_key) {
    _assertClass(msg, GroupElement);
    _assertClass(public_key, GroupElement);
    const ret = wasm.encrypt(msg.__wbg_ptr, public_key.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} s
* @param {ScalarNonZero} secret_key
* @returns {GroupElement}
*/
export function decrypt(s, secret_key) {
    _assertClass(s, ElGamal);
    _assertClass(secret_key, ScalarNonZero);
    const ret = wasm.decrypt(s.__wbg_ptr, secret_key.__wbg_ptr);
    return GroupElement.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} r
* @returns {ElGamal}
*/
export function rerandomize(v, r) {
    _assertClass(v, ElGamal);
    _assertClass(r, ScalarNonZero);
    const ret = wasm.rerandomize(v.__wbg_ptr, r.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} k
* @returns {ElGamal}
*/
export function rekey(v, k) {
    _assertClass(v, ElGamal);
    _assertClass(k, ScalarNonZero);
    const ret = wasm.rekey(v.__wbg_ptr, k.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} s
* @returns {ElGamal}
*/
export function reshuffle(v, s) {
    _assertClass(v, ElGamal);
    _assertClass(s, ScalarNonZero);
    const ret = wasm.reshuffle(v.__wbg_ptr, s.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} k_from
* @param {ScalarNonZero} k_to
* @returns {ElGamal}
*/
export function rekeyFromTo(v, k_from, k_to) {
    _assertClass(v, ElGamal);
    _assertClass(k_from, ScalarNonZero);
    _assertClass(k_to, ScalarNonZero);
    const ret = wasm.rekeyFromTo(v.__wbg_ptr, k_from.__wbg_ptr, k_to.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} n_from
* @param {ScalarNonZero} n_to
* @returns {ElGamal}
*/
export function reshuffleFromTo(v, n_from, n_to) {
    _assertClass(v, ElGamal);
    _assertClass(n_from, ScalarNonZero);
    _assertClass(n_to, ScalarNonZero);
    const ret = wasm.reshuffleFromTo(v.__wbg_ptr, n_from.__wbg_ptr, n_to.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} s
* @param {ScalarNonZero} k
* @returns {ElGamal}
*/
export function rsk(v, s, k) {
    _assertClass(v, ElGamal);
    _assertClass(s, ScalarNonZero);
    _assertClass(k, ScalarNonZero);
    const ret = wasm.rsk(v.__wbg_ptr, s.__wbg_ptr, k.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

/**
* @param {ElGamal} v
* @param {ScalarNonZero} s_from
* @param {ScalarNonZero} s_to
* @param {ScalarNonZero} k_from
* @param {ScalarNonZero} k_to
* @returns {ElGamal}
*/
export function rskFromTo(v, s_from, s_to, k_from, k_to) {
    _assertClass(v, ElGamal);
    _assertClass(s_from, ScalarNonZero);
    _assertClass(s_to, ScalarNonZero);
    _assertClass(k_from, ScalarNonZero);
    _assertClass(k_to, ScalarNonZero);
    const ret = wasm.rskFromTo(v.__wbg_ptr, s_from.__wbg_ptr, s_to.__wbg_ptr, k_from.__wbg_ptr, k_to.__wbg_ptr);
    return ElGamal.__wrap(ret);
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}

const BlindedGlobalSecretKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_blindedglobalsecretkey_free(ptr >>> 0, 1));
/**
*/
export class BlindedGlobalSecretKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BlindedGlobalSecretKey.prototype);
        obj.__wbg_ptr = ptr;
        BlindedGlobalSecretKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BlindedGlobalSecretKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blindedglobalsecretkey_free(ptr, 0);
    }
    /**
    * @returns {ScalarNonZero}
    */
    get 0() {
        const ret = wasm.__wbg_get_blindedglobalsecretkey_0(this.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, ScalarNonZero);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_blindedglobalsecretkey_0(this.__wbg_ptr, ptr0);
    }
    /**
    * @param {ScalarNonZero} x
    */
    constructor(x) {
        _assertClass(x, ScalarNonZero);
        var ptr0 = x.__destroy_into_raw();
        const ret = wasm.blindedglobalsecretkey_new(ptr0);
        this.__wbg_ptr = ret >>> 0;
        BlindedGlobalSecretKeyFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}

const BlindingFactorFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_blindingfactor_free(ptr >>> 0, 1));
/**
*/
export class BlindingFactor {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BlindingFactor.prototype);
        obj.__wbg_ptr = ptr;
        BlindingFactorFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    static __unwrap(jsValue) {
        if (!(jsValue instanceof BlindingFactor)) {
            return 0;
        }
        return jsValue.__destroy_into_raw();
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BlindingFactorFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blindingfactor_free(ptr, 0);
    }
    /**
    * @returns {ScalarNonZero}
    */
    get 0() {
        const ret = wasm.__wbg_get_blindedglobalsecretkey_0(this.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, ScalarNonZero);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_blindedglobalsecretkey_0(this.__wbg_ptr, ptr0);
    }
    /**
    * @param {ScalarNonZero} x
    */
    constructor(x) {
        _assertClass(x, ScalarNonZero);
        var ptr0 = x.__destroy_into_raw();
        const ret = wasm.blindedglobalsecretkey_new(ptr0);
        this.__wbg_ptr = ret >>> 0;
        BlindingFactorFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
    * @returns {BlindingFactor}
    */
    static random() {
        const ret = wasm.blindingfactor_random();
        return BlindingFactor.__wrap(ret);
    }
    /**
    * @returns {BlindingFactor}
    */
    clone() {
        const ret = wasm.blindingfactor_clone(this.__wbg_ptr);
        return BlindingFactor.__wrap(ret);
    }
}

const DataPointFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_datapoint_free(ptr >>> 0, 1));
/**
*/
export class DataPoint {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(DataPoint.prototype);
        obj.__wbg_ptr = ptr;
        DataPointFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DataPointFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_datapoint_free(ptr, 0);
    }
    /**
    * @returns {GroupElement}
    */
    get value() {
        const ret = wasm.__wbg_get_datapoint_value(this.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {GroupElement} arg0
    */
    set value(arg0) {
        _assertClass(arg0, GroupElement);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_datapoint_value(this.__wbg_ptr, ptr0);
    }
    /**
    * @param {GroupElement} x
    */
    constructor(x) {
        _assertClass(x, GroupElement);
        var ptr0 = x.__destroy_into_raw();
        const ret = wasm.datapoint_new(ptr0);
        this.__wbg_ptr = ret >>> 0;
        DataPointFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}

const ElGamalFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_elgamal_free(ptr >>> 0, 1));
/**
*/
export class ElGamal {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ElGamal.prototype);
        obj.__wbg_ptr = ptr;
        ElGamalFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ElGamalFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_elgamal_free(ptr, 0);
    }
    /**
    * @returns {Uint8Array}
    */
    encode() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.elgamal_encode(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} v
    * @returns {ElGamal | undefined}
    */
    static decode(v) {
        const ptr0 = passArray8ToWasm0(v, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.elgamal_decode(ptr0, len0);
        return ret === 0 ? undefined : ElGamal.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    toBase64() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.elgamal_toBase64(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * @param {string} s
    * @returns {ElGamal | undefined}
    */
    static fromBase64(s) {
        const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.elgamal_fromBase64(ptr0, len0);
        return ret === 0 ? undefined : ElGamal.__wrap(ret);
    }
}

const EncryptedDataPointFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encrypteddatapoint_free(ptr >>> 0, 1));
/**
*/
export class EncryptedDataPoint {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(EncryptedDataPoint.prototype);
        obj.__wbg_ptr = ptr;
        EncryptedDataPointFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptedDataPointFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encrypteddatapoint_free(ptr, 0);
    }
    /**
    * @returns {ElGamal}
    */
    get value() {
        const ret = wasm.__wbg_get_encrypteddatapoint_value(this.__wbg_ptr);
        return ElGamal.__wrap(ret);
    }
    /**
    * @param {ElGamal} arg0
    */
    set value(arg0) {
        _assertClass(arg0, ElGamal);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_encrypteddatapoint_value(this.__wbg_ptr, ptr0);
    }
}

const EncryptedPseudonymFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encryptedpseudonym_free(ptr >>> 0, 1));
/**
*/
export class EncryptedPseudonym {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(EncryptedPseudonym.prototype);
        obj.__wbg_ptr = ptr;
        EncryptedPseudonymFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptedPseudonymFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptedpseudonym_free(ptr, 0);
    }
    /**
    * @returns {ElGamal}
    */
    get value() {
        const ret = wasm.__wbg_get_encrypteddatapoint_value(this.__wbg_ptr);
        return ElGamal.__wrap(ret);
    }
    /**
    * @param {ElGamal} arg0
    */
    set value(arg0) {
        _assertClass(arg0, ElGamal);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_encrypteddatapoint_value(this.__wbg_ptr, ptr0);
    }
}

const GlobalKeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_globalkeypair_free(ptr >>> 0, 1));
/**
*/
export class GlobalKeyPair {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(GlobalKeyPair.prototype);
        obj.__wbg_ptr = ptr;
        GlobalKeyPairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GlobalKeyPairFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_globalkeypair_free(ptr, 0);
    }
    /**
    * @returns {GlobalPublicKey}
    */
    get public() {
        const ret = wasm.__wbg_get_globalkeypair_public(this.__wbg_ptr);
        return GlobalPublicKey.__wrap(ret);
    }
    /**
    * @param {GlobalPublicKey} arg0
    */
    set public(arg0) {
        _assertClass(arg0, GlobalPublicKey);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_globalkeypair_public(this.__wbg_ptr, ptr0);
    }
    /**
    * @returns {GlobalSecretKey}
    */
    get secret() {
        const ret = wasm.__wbg_get_globalkeypair_secret(this.__wbg_ptr);
        return GlobalSecretKey.__wrap(ret);
    }
    /**
    * @param {GlobalSecretKey} arg0
    */
    set secret(arg0) {
        _assertClass(arg0, GlobalSecretKey);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_globalkeypair_secret(this.__wbg_ptr, ptr0);
    }
}

const GlobalPublicKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_globalpublickey_free(ptr >>> 0, 1));
/**
*/
export class GlobalPublicKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(GlobalPublicKey.prototype);
        obj.__wbg_ptr = ptr;
        GlobalPublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GlobalPublicKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_globalpublickey_free(ptr, 0);
    }
    /**
    * @returns {GroupElement}
    */
    get 0() {
        const ret = wasm.__wbg_get_datapoint_value(this.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {GroupElement} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, GroupElement);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_datapoint_value(this.__wbg_ptr, ptr0);
    }
}

const GlobalSecretKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_globalsecretkey_free(ptr >>> 0, 1));
/**
*/
export class GlobalSecretKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(GlobalSecretKey.prototype);
        obj.__wbg_ptr = ptr;
        GlobalSecretKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GlobalSecretKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_globalsecretkey_free(ptr, 0);
    }
    /**
    * @returns {ScalarNonZero}
    */
    get 0() {
        const ret = wasm.__wbg_get_globalsecretkey_0(this.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, ScalarNonZero);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_globalsecretkey_0(this.__wbg_ptr, ptr0);
    }
}

const GroupElementFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_groupelement_free(ptr >>> 0, 1));
/**
*/
export class GroupElement {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(GroupElement.prototype);
        obj.__wbg_ptr = ptr;
        GroupElementFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GroupElementFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_groupelement_free(ptr, 0);
    }
    /**
    * @returns {Uint8Array}
    */
    encode() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.groupelement_encode(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {GroupElement | undefined}
    */
    static decode(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.groupelement_decode(ptr0, len0);
        return ret === 0 ? undefined : GroupElement.__wrap(ret);
    }
    /**
    * @returns {GroupElement}
    */
    static random() {
        const ret = wasm.groupelement_random();
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {Uint8Array} v
    * @returns {GroupElement}
    */
    static fromHash(v) {
        const ptr0 = passArray8ToWasm0(v, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.groupelement_fromHash(ptr0, len0);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {string} hex
    * @returns {GroupElement | undefined}
    */
    static fromHex(hex) {
        const ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.groupelement_fromHex(ptr0, len0);
        return ret === 0 ? undefined : GroupElement.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    toHex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.groupelement_toHex(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * @returns {string}
    */
    toBase64() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.groupelement_toBase64(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * @param {string} s
    * @returns {GroupElement | undefined}
    */
    static fromBase64(s) {
        const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.groupelement_fromBase64(ptr0, len0);
        return ret === 0 ? undefined : GroupElement.__wrap(ret);
    }
    /**
    * @returns {GroupElement}
    */
    static identity() {
        const ret = wasm.groupelement_identity();
        return GroupElement.__wrap(ret);
    }
    /**
    * @returns {GroupElement}
    */
    static G() {
        const ret = wasm.groupelement_G();
        return GroupElement.__wrap(ret);
    }
    /**
    * @returns {GroupElement}
    */
    static generator() {
        const ret = wasm.groupelement_G();
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {GroupElement} other
    * @returns {GroupElement}
    */
    add(other) {
        _assertClass(other, GroupElement);
        const ret = wasm.groupelement_add(this.__wbg_ptr, other.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {GroupElement} other
    * @returns {GroupElement}
    */
    sub(other) {
        _assertClass(other, GroupElement);
        const ret = wasm.groupelement_sub(this.__wbg_ptr, other.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} other
    * @returns {GroupElement}
    */
    mul(other) {
        _assertClass(other, ScalarNonZero);
        const ret = wasm.groupelement_mul(this.__wbg_ptr, other.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
}

const PEPClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pepclient_free(ptr >>> 0, 1));
/**
*/
export class PEPClient {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PEPClientFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pepclient_free(ptr, 0);
    }
    /**
    * @param {BlindedGlobalSecretKey} blinded_global_private_key
    * @param {(SessionKeyShare)[]} session_key_shares
    */
    constructor(blinded_global_private_key, session_key_shares) {
        _assertClass(blinded_global_private_key, BlindedGlobalSecretKey);
        const ptr0 = passArrayJsValueToWasm0(session_key_shares, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.pepclient_new(blinded_global_private_key.__wbg_ptr, ptr0, len0);
        this.__wbg_ptr = ret >>> 0;
        PEPClientFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
    * @param {EncryptedPseudonym} p
    * @returns {Pseudonym}
    */
    decryptPseudonym(p) {
        _assertClass(p, EncryptedPseudonym);
        const ret = wasm.pepclient_decryptData(this.__wbg_ptr, p.__wbg_ptr);
        return Pseudonym.__wrap(ret);
    }
    /**
    * @param {EncryptedDataPoint} data
    * @returns {DataPoint}
    */
    decryptData(data) {
        _assertClass(data, EncryptedDataPoint);
        const ret = wasm.pepclient_decryptData(this.__wbg_ptr, data.__wbg_ptr);
        return DataPoint.__wrap(ret);
    }
    /**
    * @param {DataPoint} data
    * @returns {EncryptedDataPoint}
    */
    encryptData(data) {
        _assertClass(data, DataPoint);
        const ret = wasm.pepclient_encryptData(this.__wbg_ptr, data.__wbg_ptr);
        return EncryptedDataPoint.__wrap(ret);
    }
    /**
    * @param {Pseudonym} p
    * @returns {EncryptedPseudonym}
    */
    encryptPseudonym(p) {
        _assertClass(p, Pseudonym);
        const ret = wasm.pepclient_encryptData(this.__wbg_ptr, p.__wbg_ptr);
        return EncryptedPseudonym.__wrap(ret);
    }
    /**
    * @param {EncryptedPseudonym} encrypted
    * @returns {EncryptedPseudonym}
    */
    rerandomizePseudonym(encrypted) {
        _assertClass(encrypted, EncryptedPseudonym);
        const ret = wasm.pepclient_rerandomizeData(this.__wbg_ptr, encrypted.__wbg_ptr);
        return EncryptedPseudonym.__wrap(ret);
    }
    /**
    * @param {EncryptedDataPoint} encrypted
    * @returns {EncryptedDataPoint}
    */
    rerandomizeData(encrypted) {
        _assertClass(encrypted, EncryptedDataPoint);
        const ret = wasm.pepclient_rerandomizeData(this.__wbg_ptr, encrypted.__wbg_ptr);
        return EncryptedDataPoint.__wrap(ret);
    }
}

const PEPSystemFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pepsystem_free(ptr >>> 0, 1));
/**
*/
export class PEPSystem {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PEPSystemFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pepsystem_free(ptr, 0);
    }
    /**
    * @param {string} pseudonymisation_secret
    * @param {string} rekeying_secret
    * @param {BlindingFactor} blinding_factor
    */
    constructor(pseudonymisation_secret, rekeying_secret, blinding_factor) {
        const ptr0 = passStringToWasm0(pseudonymisation_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(rekeying_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        _assertClass(blinding_factor, BlindingFactor);
        const ret = wasm.pepsystem_new(ptr0, len0, ptr1, len1, blinding_factor.__wbg_ptr);
        this.__wbg_ptr = ret >>> 0;
        PEPSystemFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
    * @param {string} context
    * @returns {SessionKeyShare}
    */
    sessionKeyShare(context) {
        const ptr0 = passStringToWasm0(context, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.pepsystem_sessionKeyShare(this.__wbg_ptr, ptr0, len0);
        return SessionKeyShare.__wrap(ret);
    }
    /**
    * @param {EncryptedDataPoint} p
    * @param {string} from_session
    * @param {string} to_session
    * @returns {EncryptedDataPoint}
    */
    rekey(p, from_session, to_session) {
        _assertClass(p, EncryptedDataPoint);
        const ptr0 = passStringToWasm0(from_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(to_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.pepsystem_rekey(this.__wbg_ptr, p.__wbg_ptr, ptr0, len0, ptr1, len1);
        return EncryptedDataPoint.__wrap(ret);
    }
    /**
    * @param {EncryptedPseudonym} p
    * @param {string} from_context
    * @param {string} to_context
    * @param {string} from_session
    * @param {string} to_session
    * @returns {EncryptedPseudonym}
    */
    pseudonymize(p, from_context, to_context, from_session, to_session) {
        _assertClass(p, EncryptedPseudonym);
        const ptr0 = passStringToWasm0(from_context, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(to_context, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(from_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(to_session, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.pepsystem_pseudonymize(this.__wbg_ptr, p.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        return EncryptedPseudonym.__wrap(ret);
    }
    /**
    * @param {EncryptedPseudonym} encrypted
    * @returns {EncryptedPseudonym}
    */
    rerandomizePseudonym(encrypted) {
        _assertClass(encrypted, EncryptedPseudonym);
        const ret = wasm.pepsystem_rerandomizeData(this.__wbg_ptr, encrypted.__wbg_ptr);
        return EncryptedPseudonym.__wrap(ret);
    }
    /**
    * @param {EncryptedDataPoint} encrypted
    * @returns {EncryptedDataPoint}
    */
    rerandomizeData(encrypted) {
        _assertClass(encrypted, EncryptedDataPoint);
        const ret = wasm.pepsystem_rerandomizeData(this.__wbg_ptr, encrypted.__wbg_ptr);
        return EncryptedDataPoint.__wrap(ret);
    }
}

const PseudonymFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pseudonym_free(ptr >>> 0, 1));
/**
*/
export class Pseudonym {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Pseudonym.prototype);
        obj.__wbg_ptr = ptr;
        PseudonymFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PseudonymFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pseudonym_free(ptr, 0);
    }
    /**
    * @returns {GroupElement}
    */
    get value() {
        const ret = wasm.__wbg_get_datapoint_value(this.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {GroupElement} arg0
    */
    set value(arg0) {
        _assertClass(arg0, GroupElement);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_datapoint_value(this.__wbg_ptr, ptr0);
    }
    /**
    * @param {GroupElement} x
    */
    constructor(x) {
        _assertClass(x, GroupElement);
        var ptr0 = x.__destroy_into_raw();
        const ret = wasm.datapoint_new(ptr0);
        this.__wbg_ptr = ret >>> 0;
        PseudonymFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
    * @returns {Pseudonym}
    */
    static random() {
        const ret = wasm.pseudonym_random();
        return Pseudonym.__wrap(ret);
    }
}

const ScalarCanBeZeroFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_scalarcanbezero_free(ptr >>> 0, 1));
/**
*/
export class ScalarCanBeZero {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ScalarCanBeZero.prototype);
        obj.__wbg_ptr = ptr;
        ScalarCanBeZeroFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ScalarCanBeZeroFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_scalarcanbezero_free(ptr, 0);
    }
    /**
    * @returns {Uint8Array}
    */
    encode() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.scalarcanbezero_encode(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {ScalarCanBeZero | undefined}
    */
    static decode(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.scalarcanbezero_decode(ptr0, len0);
        return ret === 0 ? undefined : ScalarCanBeZero.__wrap(ret);
    }
    /**
    * @param {string} hex
    * @returns {ScalarCanBeZero | undefined}
    */
    static fromHex(hex) {
        const ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.scalarcanbezero_fromHex(ptr0, len0);
        return ret === 0 ? undefined : ScalarCanBeZero.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    toHex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.scalarcanbezero_toHex(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * @returns {ScalarCanBeZero}
    */
    static one() {
        const ret = wasm.scalarcanbezero_one();
        return ScalarCanBeZero.__wrap(ret);
    }
    /**
    * @returns {ScalarCanBeZero}
    */
    static zero() {
        const ret = wasm.scalarcanbezero_zero();
        return ScalarCanBeZero.__wrap(ret);
    }
    /**
    * @returns {boolean}
    */
    isZero() {
        const ret = wasm.scalarcanbezero_isZero(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
    * @param {ScalarCanBeZero} other
    * @returns {ScalarCanBeZero}
    */
    add(other) {
        _assertClass(other, ScalarCanBeZero);
        const ret = wasm.scalarcanbezero_add(this.__wbg_ptr, other.__wbg_ptr);
        return ScalarCanBeZero.__wrap(ret);
    }
    /**
    * @param {ScalarCanBeZero} other
    * @returns {ScalarCanBeZero}
    */
    sub(other) {
        _assertClass(other, ScalarCanBeZero);
        const ret = wasm.scalarcanbezero_sub(this.__wbg_ptr, other.__wbg_ptr);
        return ScalarCanBeZero.__wrap(ret);
    }
    /**
    * @returns {ScalarNonZero | undefined}
    */
    toNonZero() {
        const ret = wasm.scalarcanbezero_toNonZero(this.__wbg_ptr);
        return ret === 0 ? undefined : ScalarNonZero.__wrap(ret);
    }
}

const ScalarNonZeroFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_scalarnonzero_free(ptr >>> 0, 1));
/**
*/
export class ScalarNonZero {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ScalarNonZero.prototype);
        obj.__wbg_ptr = ptr;
        ScalarNonZeroFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ScalarNonZeroFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_scalarnonzero_free(ptr, 0);
    }
    /**
    * @returns {Uint8Array}
    */
    encode() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.scalarcanbezero_encode(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {ScalarNonZero | undefined}
    */
    static decode(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.scalarnonzero_decode(ptr0, len0);
        return ret === 0 ? undefined : ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {string} hex
    * @returns {ScalarNonZero | undefined}
    */
    static fromHex(hex) {
        const ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.scalarnonzero_fromHex(ptr0, len0);
        return ret === 0 ? undefined : ScalarNonZero.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    toHex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.scalarcanbezero_toHex(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * @returns {ScalarNonZero}
    */
    static random() {
        const ret = wasm.scalarnonzero_random();
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {Uint8Array} v
    * @returns {ScalarNonZero}
    */
    static fromHash(v) {
        const ptr0 = passArray8ToWasm0(v, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.scalarnonzero_fromHash(ptr0, len0);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @returns {ScalarNonZero}
    */
    static one() {
        const ret = wasm.scalarcanbezero_one();
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @returns {ScalarNonZero}
    */
    invert() {
        const ret = wasm.scalarnonzero_invert(this.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} other
    * @returns {ScalarNonZero}
    */
    mul(other) {
        _assertClass(other, ScalarNonZero);
        const ret = wasm.scalarnonzero_mul(this.__wbg_ptr, other.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @returns {ScalarCanBeZero}
    */
    toCanBeZero() {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.scalarnonzero_toCanBeZero(ptr);
        return ScalarCanBeZero.__wrap(ret);
    }
}

const SessionKeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sessionkeypair_free(ptr >>> 0, 1));
/**
*/
export class SessionKeyPair {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SessionKeyPair.prototype);
        obj.__wbg_ptr = ptr;
        SessionKeyPairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SessionKeyPairFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sessionkeypair_free(ptr, 0);
    }
    /**
    * @returns {SessionPublicKey}
    */
    get public() {
        const ret = wasm.__wbg_get_globalkeypair_public(this.__wbg_ptr);
        return SessionPublicKey.__wrap(ret);
    }
    /**
    * @param {SessionPublicKey} arg0
    */
    set public(arg0) {
        _assertClass(arg0, SessionPublicKey);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_globalkeypair_public(this.__wbg_ptr, ptr0);
    }
    /**
    * @returns {SessionSecretKey}
    */
    get secret() {
        const ret = wasm.__wbg_get_globalkeypair_secret(this.__wbg_ptr);
        return SessionSecretKey.__wrap(ret);
    }
    /**
    * @param {SessionSecretKey} arg0
    */
    set secret(arg0) {
        _assertClass(arg0, SessionSecretKey);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_globalkeypair_secret(this.__wbg_ptr, ptr0);
    }
}

const SessionKeyShareFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sessionkeyshare_free(ptr >>> 0, 1));
/**
*/
export class SessionKeyShare {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SessionKeyShare.prototype);
        obj.__wbg_ptr = ptr;
        SessionKeyShareFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    static __unwrap(jsValue) {
        if (!(jsValue instanceof SessionKeyShare)) {
            return 0;
        }
        return jsValue.__destroy_into_raw();
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SessionKeyShareFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sessionkeyshare_free(ptr, 0);
    }
    /**
    * @returns {ScalarNonZero}
    */
    get 0() {
        const ret = wasm.__wbg_get_blindedglobalsecretkey_0(this.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, ScalarNonZero);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_blindedglobalsecretkey_0(this.__wbg_ptr, ptr0);
    }
    /**
    * @param {ScalarNonZero} x
    */
    constructor(x) {
        _assertClass(x, ScalarNonZero);
        var ptr0 = x.__destroy_into_raw();
        const ret = wasm.blindedglobalsecretkey_new(ptr0);
        this.__wbg_ptr = ret >>> 0;
        SessionKeyShareFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}

const SessionPublicKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sessionpublickey_free(ptr >>> 0, 1));
/**
*/
export class SessionPublicKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SessionPublicKey.prototype);
        obj.__wbg_ptr = ptr;
        SessionPublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SessionPublicKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sessionpublickey_free(ptr, 0);
    }
    /**
    * @returns {GroupElement}
    */
    get 0() {
        const ret = wasm.__wbg_get_datapoint_value(this.__wbg_ptr);
        return GroupElement.__wrap(ret);
    }
    /**
    * @param {GroupElement} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, GroupElement);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_datapoint_value(this.__wbg_ptr, ptr0);
    }
}

const SessionSecretKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sessionsecretkey_free(ptr >>> 0, 1));
/**
*/
export class SessionSecretKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SessionSecretKey.prototype);
        obj.__wbg_ptr = ptr;
        SessionSecretKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SessionSecretKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sessionsecretkey_free(ptr, 0);
    }
    /**
    * @returns {ScalarNonZero}
    */
    get 0() {
        const ret = wasm.__wbg_get_globalsecretkey_0(this.__wbg_ptr);
        return ScalarNonZero.__wrap(ret);
    }
    /**
    * @param {ScalarNonZero} arg0
    */
    set 0(arg0) {
        _assertClass(arg0, ScalarNonZero);
        var ptr0 = arg0.__destroy_into_raw();
        wasm.__wbg_set_globalsecretkey_0(this.__wbg_ptr, ptr0);
    }
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbindgen_object_drop_ref = function(arg0) {
        takeObject(arg0);
    };
    imports.wbg.__wbg_sessionkeyshare_unwrap = function(arg0) {
        const ret = SessionKeyShare.__unwrap(takeObject(arg0));
        return ret;
    };
    imports.wbg.__wbg_blindingfactor_unwrap = function(arg0) {
        const ret = BlindingFactor.__unwrap(takeObject(arg0));
        return ret;
    };
    imports.wbg.__wbg_crypto_1d1f22824a6a080c = function(arg0) {
        const ret = getObject(arg0).crypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = getObject(arg0);
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbg_process_4a72847cc503995b = function(arg0) {
        const ret = getObject(arg0).process;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_versions_f686565e586dd935 = function(arg0) {
        const ret = getObject(arg0).versions;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_node_104a2ff8d6ea03a2 = function(arg0) {
        const ret = getObject(arg0).node;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'string';
        return ret;
    };
    imports.wbg.__wbg_require_cca90b1a94a0255b = function() { return handleError(function () {
        const ret = module.require;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'function';
        return ret;
    };
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_msCrypto_eb05e62b530a1508 = function(arg0) {
        const ret = getObject(arg0).msCrypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_randomFillSync_5c9c955aa56b6049 = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).randomFillSync(takeObject(arg1));
    }, arguments) };
    imports.wbg.__wbg_getRandomValues_3aa56aa6edec874c = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).getRandomValues(getObject(arg1));
    }, arguments) };
    imports.wbg.__wbg_newnoargs_76313bd6ff35d0f2 = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_call_1084a111329e68ce = function() { return handleError(function (arg0, arg1) {
        const ret = getObject(arg0).call(getObject(arg1));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_object_clone_ref = function(arg0) {
        const ret = getObject(arg0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_self_3093d5d1f7bcb682 = function() { return handleError(function () {
        const ret = self.self;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_window_3bcfc4d31bc012f8 = function() { return handleError(function () {
        const ret = window.window;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_globalThis_86b222e13bdf32ed = function() { return handleError(function () {
        const ret = globalThis.globalThis;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_global_e5a3fe56f8be9485 = function() { return handleError(function () {
        const ret = global.global;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = getObject(arg0) === undefined;
        return ret;
    };
    imports.wbg.__wbg_call_89af060b4e1523f2 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_buffer_b7b08af79b0b0974 = function(arg0) {
        const ret = getObject(arg0).buffer;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_8a2cb9ca96b27ec9 = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_new_ea1883e1e5e86686 = function(arg0) {
        const ret = new Uint8Array(getObject(arg0));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_set_d1e79e2388520f18 = function(arg0, arg1, arg2) {
        getObject(arg0).set(getObject(arg1), arg2 >>> 0);
    };
    imports.wbg.__wbg_newwithlength_ec548f448387c968 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_subarray_7c2e3576afe181d1 = function(arg0, arg1, arg2) {
        const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return addHeapObject(ret);
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;



    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined' && Object.getPrototypeOf(module) === Object.prototype)
    ({module} = module)
    else
    console.warn('using deprecated parameters for `initSync()`; pass a single object instead')

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined' && Object.getPrototypeOf(module_or_path) === Object.prototype)
    ({module_or_path} = module_or_path)
    else
    console.warn('using deprecated parameters for the initialization function; pass a single object instead')

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('libpep_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
