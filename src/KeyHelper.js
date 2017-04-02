// import {createKeyPair, getRandomBytes, Ed25519Sign} from "./crypto";

function isNonNegativeInteger(n) {
    return (typeof n === 'number' && (n % 1) === 0  && n >= 0);
}

var KeyHelper = {
    // export const generateIdentityKeyPair = () => {};
    generateIdentityKeyPair: function() {
        // return createKeyPair();
        return Internal.crypto.createKeyPair();
    },

    // export const generateRegistrationId = () => {};
    generateRegistrationId: function() {
        // var registrationId = new Uint16Array(getRandomBytes(2))[0];
        var registrationId = new Uint16Array(Internal.crypto.getRandomBytes(2))[0];
        return registrationId & 0x3fff;
    },

    // export const generateSignedPreKey = (identityKeyPair, signedKeyId) => {};
    generateSignedPreKey: function (identityKeyPair, signedKeyId) {
        if (!(identityKeyPair.privKey instanceof ArrayBuffer) ||
            identityKeyPair.privKey.byteLength != 32 ||
            !(identityKeyPair.pubKey instanceof ArrayBuffer) ||
            identityKeyPair.pubKey.byteLength != 33) {
            throw new TypeError('Invalid argument for identityKeyPair');
        }
        if (!isNonNegativeInteger(signedKeyId)) {
            throw new TypeError(
                'Invalid argument for signedKeyId: ' + signedKeyId
            );
        }

        // return createKeyPair().then(function(keyPair) {
        return Internal.crypto.createKeyPair().then(function(keyPair) {
            // return Ed25519Sign(identityKeyPair.privKey, keyPair.pubKey).then(function(sig) {
            return Internal.crypto.Ed25519Sign(identityKeyPair.privKey, keyPair.pubKey).then(function(sig) {
                return {
                    keyId      : signedKeyId,
                    keyPair    : keyPair,
                    signature  : sig
                };
            });
        });
    },

    // export const generatePreKey = (keyId) => {};
    generatePreKey: function(keyId) {
        if (!isNonNegativeInteger(keyId)) {
            throw new TypeError('Invalid argument for keyId: ' + keyId);
        }

        // return createKeyPair().then(function(keyPair) {
        return Internal.crypto.createKeyPair().then(function(keyPair) {
            return { keyId: keyId, keyPair: keyPair };
        });
    }
};

libsignal.KeyHelper = KeyHelper;
