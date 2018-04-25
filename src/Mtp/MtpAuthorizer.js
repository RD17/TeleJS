//import requestLib from 'request-promise-native'
import { TLSerialization, TLDeserialization } from '../TL'
import { MtpTimeManager, MtpDcConfigurator, MtpRsaKeysManager } from '../Mtp'
import {
    BigInteger, nextRandomInt, dT, bytesToHex, bytesCmp,  pqPrimeFactorization, SecureRandom, sha1BytesSync, rsaEncrypt,
    tsNow, aesDecryptSync, aesEncryptSync, bytesToArrayBuffer, bytesFromHex, bytesModPow, bytesXor
} from '../Utils'
import { LogService, ErrorResponse } from '../Services'
import { networkRequest } from '../network'

const mtpSendPlainRequest = (dcID, requestBuffer) => new Promise((resolve, reject) => {
    var requestLength = requestBuffer.byteLength,
        requestArray = new Int32Array(requestBuffer)

    var header = new TLSerialization()
    header.storeLongP(0, 0, 'auth_key_id') // Auth key
    header.storeLong(MtpTimeManager.generateID(), 'msg_id') // Msg_id
    header.storeInt(requestLength, 'request_length')

    var headerBuffer = header.getBuffer(),
        headerArray = new Int32Array(headerBuffer)
    var headerLength = headerBuffer.byteLength

    var resultBuffer = new ArrayBuffer(headerLength + requestLength),
        resultArray = new Int32Array(resultBuffer)

    resultArray.set(headerArray)
    resultArray.set(requestArray, headerArray.length)

    var requestData = resultArray
    var url = MtpDcConfigurator.chooseServer(dcID)
    var baseError = { code: 406, type: 'NETWORK_BAD_RESPONSE', url: url }

    networkRequest(url, resultArray).then((result) => {
        if (!result.data || !result.data.byteLength) {
            reject(baseError)
        }

        const deserializer = new TLDeserialization(result.data, { mtproto: true })
        const auth_key_id = deserializer.fetchLong('auth_key_id')
        const msg_id = deserializer.fetchLong('msg_id')
        const msg_len = deserializer.fetchInt('msg_len')

        resolve(deserializer)
    })
        .catch(err => reject({ ...baseError, originalError: err }))
})

function mtpSendReqPQ(auth) {
    var deferred = auth.deferred

    var request = new TLSerialization({ mtproto: true })

    request.storeMethod('req_pq', { nonce: auth.nonce })

    LogService.logVerbose(`[MtpAuthorizer] mtpSendReqPQ() Send req_pq ${bytesToHex(auth.nonce)}`)

    mtpSendPlainRequest(auth.dcID, request.getBuffer())
        .then((deserializer) => {

            var response = deserializer.fetchObject('ResPQ')

            if (response._ != 'resPQ') {
                throw new Error('[MT] resPQ response invalid: ' + response._)
            }

            if (!bytesCmp(auth.nonce, response.nonce)) {
                throw new Error('[MT] resPQ nonce mismatch')
            }

            auth.serverNonce = response.server_nonce
            auth.pq = response.pq
            auth.fingerprints = response.server_public_key_fingerprints

            LogService.logVerbose(`[MtpAuthorizer] mtpSendReqPQ() Got ResPQ ${bytesToHex(auth.serverNonce)} ${bytesToHex(auth.pq)} ${auth.fingerprints}`)

            auth.publicKey = MtpRsaKeysManager.select(auth.fingerprints)

            if (!auth.publicKey) {
                throw new Error('[MT] No public key found')
            }

            LogService.logVerbose(`[MtpAuthorizer] mtpSendReqPQ() 'PQ factorization start ${auth.pq}`)

            const pAndQ = pqPrimeFactorization(auth.pq)

            if (!pAndQ) {
                throw new Error('Error factorizing p and q')
            }

            auth.p = pAndQ[0]
            auth.q = pAndQ[1]

            LogService.logVerbose(`[MtpAuthorizer] mtpSendReqPQ() 'PQ factorization done ${pAndQ[2]}`)

            mtpSendReqDhParams(auth)
        })
        .catch(err => {
            LogService.logError(`[MtpAuthorizer] mtpSendReqPQ() ${new ErrorResponse(err)}`)
            deferred.reject(err)
        })

    MtpRsaKeysManager.prepare()
}

function mtpSendReqDhParams(auth) {
    var deferred = auth.deferred

    auth.newNonce = new Array(32)
    new SecureRandom().nextBytes(auth.newNonce)

    var data = new TLSerialization({ mtproto: true })
    data.storeObject({
        _: 'p_q_inner_data',
        pq: auth.pq,
        p: auth.p,
        q: auth.q,
        nonce: auth.nonce,
        server_nonce: auth.serverNonce,
        new_nonce: auth.newNonce
    }, 'P_Q_inner_data', 'DECRYPTED_DATA')

    var dataWithHash = sha1BytesSync(data.getBuffer()).concat(data.getBytes())

    var request = new TLSerialization({ mtproto: true })
    request.storeMethod('req_DH_params', {
        nonce: auth.nonce,
        server_nonce: auth.serverNonce,
        p: auth.p,
        q: auth.q,
        public_key_fingerprint: auth.publicKey.fingerprint,
        encrypted_data: rsaEncrypt(auth.publicKey, dataWithHash)
    })

    LogService.logVerbose(`[MtpAuthorizer] mtpSendReqDhParams()`)

    mtpSendPlainRequest(auth.dcID, request.getBuffer()).then(function (deserializer) {
        var response = deserializer.fetchObject('Server_DH_Params', 'RESPONSE')

        if (response._ != 'server_DH_params_fail' && response._ != 'server_DH_params_ok') {
            deferred.reject(new Error('[MT] Server_DH_Params response invalid: ' + response._))
            return false
        }

        if (!bytesCmp(auth.nonce, response.nonce)) {
            deferred.reject(new Error('[MT] Server_DH_Params nonce mismatch'))
            return false
        }

        if (!bytesCmp(auth.serverNonce, response.server_nonce)) {
            deferred.reject(new Error('[MT] Server_DH_Params server_nonce mismatch'))
            return false
        }

        if (response._ == 'server_DH_params_fail') {
            var newNonceHash = sha1BytesSync(auth.newNonce).slice(-16)
            if (!bytesCmp(newNonceHash, response.new_nonce_hash)) {
                deferred.reject(new Error('[MT] server_DH_params_fail new_nonce_hash mismatch'))
                return false
            }
            deferred.reject(new Error('[MT] server_DH_params_fail'))
            return false
        }

        try {
            mtpDecryptServerDhDataAnswer(auth, response.encrypted_answer)
        } catch (e) {
            deferred.reject(e)
            return false
        }

        mtpSendSetClientDhParams(auth)
    }, function (error) {
        deferred.reject(error)
    })
}

function mtpDecryptServerDhDataAnswer(auth, encryptedAnswer) {
    auth.localTime = tsNow()

    auth.tmpAesKey = sha1BytesSync(auth.newNonce.concat(auth.serverNonce)).concat(sha1BytesSync(auth.serverNonce.concat(auth.newNonce)).slice(0, 12))
    auth.tmpAesIv = sha1BytesSync(auth.serverNonce.concat(auth.newNonce)).slice(12).concat(sha1BytesSync([].concat(auth.newNonce, auth.newNonce)), auth.newNonce.slice(0, 4))

    var answerWithHash = aesDecryptSync(encryptedAnswer, auth.tmpAesKey, auth.tmpAesIv)

    var hash = answerWithHash.slice(0, 20)
    var answerWithPadding = answerWithHash.slice(20)
    var buffer = bytesToArrayBuffer(answerWithPadding)

    var deserializer = new TLDeserialization(buffer, { mtproto: true })
    var response = deserializer.fetchObject('Server_DH_inner_data')

    if (response._ != 'server_DH_inner_data') {
        throw new Error('[MT] server_DH_inner_data response invalid: ' + constructor)
    }

    if (!bytesCmp(auth.nonce, response.nonce)) {
        throw new Error('[MT] server_DH_inner_data nonce mismatch')
    }

    if (!bytesCmp(auth.serverNonce, response.server_nonce)) {
        throw new Error('[MT] server_DH_inner_data serverNonce mismatch')
    }

    LogService.logVerbose(`[MtpAuthorizer] mtpDecryptServerDhDataAnswer() Done decrypting answer`)

    auth.g = response.g
    auth.dhPrime = response.dh_prime
    auth.gA = response.g_a
    auth.serverTime = response.server_time
    auth.retry = 0

    mtpVerifyDhParams(auth.g, auth.dhPrime, auth.gA)

    var offset = deserializer.getOffset()

    if (!bytesCmp(hash, sha1BytesSync(answerWithPadding.slice(0, offset)))) {
        throw new Error('[MT] server_DH_inner_data SHA1-hash mismatch')
    }


    MtpTimeManager.applyServerTime(auth.serverTime, auth.localTime)
}

function mtpVerifyDhParams(g, dhPrime, gA) {
    LogService.logVerbose(`[MtpAuthorizer] mtpVerifyDhParams() Verifying DH params`)

    var dhPrimeHex = bytesToHex(dhPrime)
    if (g != 3 ||
        dhPrimeHex !== 'c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c3720fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b') {
        // The verified value is from https://core.telegram.org/mtproto/security_guidelines
        throw new Error('[MT] DH params are not verified: unknown dhPrime')
    }

    LogService.logVerbose(`[MtpAuthorizer] mtpVerifyDhParams() dhPrime cmp OK`)

    var gABigInt = new BigInteger(bytesToHex(gA), 16)
    var dhPrimeBigInt = new BigInteger(dhPrimeHex, 16)

    if (gABigInt.compareTo(BigInteger.ONE) <= 0) {
        throw new Error('[MT] DH params are not verified: gA <= 1')
    }

    if (gABigInt.compareTo(dhPrimeBigInt.subtract(BigInteger.ONE)) >= 0) {
        throw new Error('[MT] DH params are not verified: gA >= dhPrime - 1')
    }

    LogService.logVerbose(`[MtpAuthorizer] mtpVerifyDhParams() 1 < gA < dhPrime-1 OK`)

    var two = new BigInteger(null)
    two.fromInt(2)
    var twoPow = two.pow(2048 - 64)

    if (gABigInt.compareTo(twoPow) < 0) {
        throw new Error('[MT] DH params are not verified: gA < 2^{2048-64}')
    }
    if (gABigInt.compareTo(dhPrimeBigInt.subtract(twoPow)) >= 0) {
        throw new Error('[MT] DH params are not verified: gA > dhPrime - 2^{2048-64}')
    }

    LogService.logVerbose(`[MtpAuthorizer] mtpVerifyDhParams() 2^{2048-64} < gA < dhPrime-2^{2048-64} OK`)

    return true
}

function mtpSendSetClientDhParams(auth) {
    var deferred = auth.deferred
    var gBytes = bytesFromHex(auth.g.toString(16))

    auth.b = new Array(256)
    new SecureRandom().nextBytes(auth.b)

    let gB = bytesModPow(gBytes, auth.b, auth.dhPrime)
    var data = new TLSerialization({ mtproto: true })
    data.storeObject({
        _: 'client_DH_inner_data',
        nonce: auth.nonce,
        server_nonce: auth.serverNonce,
        retry_id: [0, auth.retry++],
        g_b: gB
    }, 'Client_DH_Inner_Data')

    var dataWithHash = sha1BytesSync(data.getBuffer()).concat(data.getBytes())

    var encryptedData = aesEncryptSync(dataWithHash, auth.tmpAesKey, auth.tmpAesIv)

    var request = new TLSerialization({ mtproto: true })
    request.storeMethod('set_client_DH_params', {
        nonce: auth.nonce,
        server_nonce: auth.serverNonce,
        encrypted_data: encryptedData
    })

    LogService.logVerbose(`[MtpAuthorizer] mtpSendSetClientDhParams() Send set_client_DH_params`)

    mtpSendPlainRequest(auth.dcID, request.getBuffer()).then(function (deserializer) {
        var response = deserializer.fetchObject('Set_client_DH_params_answer')

        if (response._ != 'dh_gen_ok' && response._ != 'dh_gen_retry' && response._ != 'dh_gen_fail') {
            deferred.reject(new Error('[MT] Set_client_DH_params_answer response invalid: ' + response._))
            return false
        }

        if (!bytesCmp(auth.nonce, response.nonce)) {
            deferred.reject(new Error('[MT] Set_client_DH_params_answer nonce mismatch'))
            return false
        }

        if (!bytesCmp(auth.serverNonce, response.server_nonce)) {
            deferred.reject(new Error('[MT] Set_client_DH_params_answer server_nonce mismatch'))
            return false
        }

        let authKey = bytesModPow(auth.gA, auth.b, auth.dhPrime)
        var authKeyHash = sha1BytesSync(authKey),
            authKeyAux = authKeyHash.slice(0, 8),
            authKeyID = authKeyHash.slice(-8)

        LogService.logVerbose(`[MtpAuthorizer] mtpSendSetClientDhParams() Got Set_client_DH_params_answer ${response._}`)

        switch (response._) {
            case 'dh_gen_ok':
                var newNonceHash1 = sha1BytesSync(auth.newNonce.concat([1], authKeyAux)).slice(-16)

                if (!bytesCmp(newNonceHash1, response.new_nonce_hash1)) {
                    deferred.reject(new Error('[MT] Set_client_DH_params_answer new_nonce_hash1 mismatch'))
                    return false
                }

                var serverSalt = bytesXor(auth.newNonce.slice(0, 8), auth.serverNonce.slice(0, 8))

                auth.authKeyID = authKeyID
                auth.authKey = authKey
                auth.serverSalt = serverSalt

                deferred.resolve(auth)
                break

            case 'dh_gen_retry':
                var newNonceHash2 = sha1BytesSync(auth.newNonce.concat([2], authKeyAux)).slice(-16)
                if (!bytesCmp(newNonceHash2, response.new_nonce_hash2)) {
                    deferred.reject(new Error('[MT] Set_client_DH_params_answer new_nonce_hash2 mismatch'))
                    return false
                }

                return mtpSendSetClientDhParams(auth)

            case 'dh_gen_fail':
                var newNonceHash3 = sha1BytesSync(auth.newNonce.concat([3], authKeyAux)).slice(-16)
                if (!bytesCmp(newNonceHash3, response.new_nonce_hash3)) {
                    deferred.reject(new Error('[MT] Set_client_DH_params_answer new_nonce_hash3 mismatch'))
                    return false
                }

                deferred.reject(new Error('[MT] Set_client_DH_params_answer fail'))
                return false
        }
    }, function (error) {
        deferred.reject(error)
    })
}

const cached = {}

const mtpAuth = (dcID) => new Promise((resolve, reject) => {
    if (cached[dcID] !== undefined) {
        return cached[dcID]
    }

    var nonce = []
    for (var i = 0; i < 16; i++) {
        nonce.push(nextRandomInt(0xFF))
    }

    if (!MtpDcConfigurator.chooseServer(dcID)) {
        throw new Error('[MT] No server found for dc ' + dcID)
    }

    var auth = {
        dcID: dcID,
        nonce: nonce,
        deferred: {
            resolve: (obj) => resolve(obj), reject: (err) => reject(err)
        }
    }

    mtpSendReqPQ(auth)
})

export const auth = mtpAuth