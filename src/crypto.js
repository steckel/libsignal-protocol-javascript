/*
 * vim: ts=4:sw=4
 */

var Internal = Internal || {};

var crypto = window.crypto;

if (!crypto || !crypto.subtle || typeof crypto.getRandomValues !== 'function') {
    throw new Error('WebCrypto not found');
}

// TODO: import {subtle, getRandomValues} from "crypto";
const {subtle, getRandomValues} = window.crypto;


Internal.crypto = {
// export const getRandomBytes = (size) => {};
    getRandomBytes: function(size) {
        var array = new Uint8Array(size);
        getRandomValues(array);
        return array.buffer;
    },
// export const encrypt = (key, data, iv) => {};
    encrypt: function(key, data, iv) {
        return subtle.importKey('raw', key, {name: 'AES-CBC'}, false, ['encrypt']).then(function(key) {
            return crypto.subtle.encrypt({name: 'AES-CBC', iv: new Uint8Array(iv)}, key, data);
        });
    },
// export const decrypt = (key, data, iv) => {};
    decrypt: function(key, data, iv) {
        return subtle.importKey('raw', key, {name: 'AES-CBC'}, false, ['decrypt']).then(function(key) {
            return crypto.subtle.decrypt({name: 'AES-CBC', iv: new Uint8Array(iv)}, key, data);
        });
    },
// export const sign = (key, data) => {};
    sign: function(key, data) {
        return subtle.importKey('raw', key, {name: 'HMAC', hash: {name: 'SHA-256'}}, false, ['sign']).then(function(key) {
            return subtle.sign( {name: 'HMAC', hash: 'SHA-256'}, key, data);
        });
    },

// export const hash = (data) => {};
    hash: function(data) {
        return subtle.digest({name: 'SHA-512'}, data);
    },

// export const HKDF = (input, salt, info) => {};
    HKDF: function(input, salt, info) {
        // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
        // TODO: We dont always need the third chunk, we might skip it
        return Internal.crypto.sign(salt, input).then(function(PRK) {
            var infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32);
            var infoArray = new Uint8Array(infoBuffer);
            infoArray.set(new Uint8Array(info), 32);
            infoArray[infoArray.length - 1] = 1;
            return Internal.crypto.sign(PRK, infoBuffer.slice(32)).then(function(T1) {
                infoArray.set(new Uint8Array(T1));
                infoArray[infoArray.length - 1] = 2;
                return Internal.crypto.sign(PRK, infoBuffer).then(function(T2) {
                    infoArray.set(new Uint8Array(T2));
                    infoArray[infoArray.length - 1] = 3;
                    return Internal.crypto.sign(PRK, infoBuffer).then(function(T3) {
                        return [ T1, T2, T3 ];
                    });
                });
            });
        });
    },

    // Curve 25519 crypto
// export const createKeyPair = (privKey) => {};
    createKeyPair: function(privKey) {
        if (privKey === undefined) {
            privKey = Internal.crypto.getRandomBytes(32);
        }
        return Internal.Curve.async.createKeyPair(privKey);
    },
// export const ECDHE = (pubKey, privKey) => {};
    ECDHE: function(pubKey, privKey) {
        return Internal.Curve.async.ECDHE(pubKey, privKey);
    },
// export const Ed25519Sign = (pubKey, message) => {};
    Ed25519Sign: function(privKey, message) {
        return Internal.Curve.async.Ed25519Sign(privKey, message);
    },
// export const Ed25519Verify = (pubKey, message) => {};
    Ed25519Verify: function(pubKey, msg, sig) {
        return Internal.Curve.async.Ed25519Verify(pubKey, msg, sig);
    }
};


// FIXME(steckel): What? Why reassign/wrap?
// HKDF for TextSecure has a bit of additional handling - salts always end up being 32 bytes
Internal.HKDF = function(input, salt, info) {
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }

    return Internal.crypto.HKDF(input, salt,  util.toArrayBuffer(info));
};

// export const verifyMAC = (data, key, mac, length) => {};
Internal.verifyMAC = function(data, key, mac, length) {
    return Internal.crypto.sign(key, data).then(function(calculated_mac) {
        if (mac.byteLength != length  || calculated_mac.byteLength < length) {
            throw new Error("Bad MAC length");
        }
        var a = new Uint8Array(calculated_mac);
        var b = new Uint8Array(mac);
        var result = 0;
        for (var i=0; i < mac.byteLength; ++i) {
            result = result | (a[i] ^ b[i]);
        }
        if (result !== 0) {
            console.log('Our MAC  ', dcodeIO.ByteBuffer.wrap(calculated_mac).toHex());
            console.log('Their MAC', dcodeIO.ByteBuffer.wrap(mac).toHex());
            throw new Error("Bad MAC");
        }
    });
};

// FIXME(steckel): libsignal Global?

libsignal.HKDF = {
    deriveSecrets: function(input, salt, info) {
        return Internal.HKDF(input, salt, info);
    }
};

libsignal.crypto = {
    encrypt: function(key, data, iv) {
        return Internal.crypto.encrypt(key, data, iv);
    },
    decrypt: function(key, data, iv) {
        return Internal.crypto.decrypt(key, data, iv);
    },
    calculateMAC: function(key, data) {
        return Internal.crypto.sign(key, data);
    },
    verifyMAC: function(data, key, mac, length) {
        return Internal.verifyMAC(data, key, mac, length);
    },
    getRandomBytes: function(size) {
        return Internal.crypto.getRandomBytes(size);
    }
};

export default Internal;
