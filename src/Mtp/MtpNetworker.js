import Config from '../config.js'
import { MtpTimeManager, MtpDcConfigurator, MtpRsaKeysManager } from '../Mtp'
import {
    SecureRandom, convertToUint8Array, convertToArrayBuffer,
    sha1BytesSync, dT, tsNow, nextRandomInt, bufferConcat, sha256HashSync, aesEncryptSync,
    bytesCmp, aesDecryptSync, bytesToArrayBuffer, bytesToHex, longToBytes, uintToInt
} from '../Utils'
import { TLSerialization, TLDeserialization } from '../TL'
import { networkRequest } from '../network'
import { setState, getState } from '../state'
import { LogService, ErrorResponse } from '../Services'

var updatesProcessor
var iii = 0,
    offline
var offlineInited = false
var akStopped = false

function MtpNetworker(dcID, authKey, serverSalt, options) {
    options = options || {}

    this.dcID = dcID
    this.iii = iii++

    this.authKey = authKey
    this.authKeyUint8 = convertToUint8Array(authKey)
    this.authKeyBuffer = convertToArrayBuffer(authKey)
    this.authKeyID = sha1BytesSync(authKey).slice(-8)

    this.serverSalt = serverSalt

    this.upload = options.fileUpload || options.fileDownload || false

    this.updateSessionId()

    this.lastServerMessages = []

    this.currentRequests = 0
    this.checkConnectionPeriod = 0

    this.sentMessages = {}
    this.clientMessages = []

    this.pendingMessages = {}
    this.pendingAcks = []
    this.pendingResends = []
    this.connectionInited = false

    this.pendingTimeouts = []

    //this.longPollInt = $interval(this.checkLongPoll.bind(this), 10000)
    /*
    this.checkLongPoll()

    if (!offlineInited) {
        offlineInited = true
        $rootScope.offline = true
        $rootScope.offlineConnecting = true
    }

    if (Config.Navigator.mobile) {
        this.setupMobileSleep()
    }
    */
}

MtpNetworker.prototype.getDcId = function () { return this.dcID }

MtpNetworker.prototype.updateSessionId = function () {
    this.seqNo = 0
    this.prevSessionID = this.sessionID
    this.sessionID = new Array(8)
    new SecureRandom().nextBytes(this.sessionID)
}

MtpNetworker.prototype.setupMobileSleep = function () {
    var self = this
    /*
    $rootScope.$watch('idle.isIDLE', function (isIDLE) {
        if (isIDLE) {
            self.sleepAfter = tsNow() + 30000
        } else {
            delete self.sleepAfter
            self.checkLongPoll()
        }
    })

    $rootScope.$on('push_received', function () {
        LogService.logVerbose(`[MtpNetworker] setupMobileSleep() push_received`)
        if (self.sleepAfter) {
            self.sleepAfter = tsNow() + 30000
            self.checkLongPoll()
        }
    })
    */
}

MtpNetworker.prototype.updateSentMessage = function (sentMessageID) {
    var sentMessage = this.sentMessages[sentMessageID]
    if (!sentMessage) {
        return false
    }
    var self = this
    if (sentMessage.container) {
        var newInner = []
        sentMessage.inner.forEach(function (innerSentMessageID) {
            var innerSentMessage = self.updateSentMessage(innerSentMessageID)
            if (innerSentMessage) {
                newInner.push(innerSentMessage.msg_id)
            }
        })
        sentMessage.inner = newInner
    }

    sentMessage.msg_id = MtpTimeManager.generateID()
    sentMessage.seq_no = this.generateSeqNo(
        sentMessage.notContentRelated ||
        sentMessage.container
    )
    this.sentMessages[sentMessage.msg_id] = sentMessage
    delete self.sentMessages[sentMessageID]

    return sentMessage
}

MtpNetworker.prototype.generateSeqNo = function (notContentRelated) {
    var seqNo = this.seqNo * 2

    if (!notContentRelated) {
        seqNo++
        this.seqNo++
    }

    return seqNo
}

MtpNetworker.prototype.wrapMtpCall = function (method, params, options) {
    var serializer = new TLSerialization({ mtproto: true })

    serializer.storeMethod(method, params)

    var messageID = MtpTimeManager.generateID()
    var seqNo = this.generateSeqNo()
    var message = {
        msg_id: messageID,
        seq_no: seqNo,
        body: serializer.getBytes()
    }

    LogService.logVerbose(`[MtpNetworker] wrapMtpCall() ${method} ${JSON.stringify(params, 0, 2)}`)

    return this.pushMessage(message, options)
}

MtpNetworker.prototype.wrapMtpMessage = function (object, options) {
    options = options || {}

    var serializer = new TLSerialization({ mtproto: true })
    serializer.storeObject(object, 'Object')

    const messageID = MtpTimeManager.generateID()
    const seqNo = this.generateSeqNo(options.notContentRelated)
    const message = {
        msg_id: messageID,
        seq_no: seqNo,
        body: serializer.getBytes()
    }

    LogService.logVerbose(`[MtpNetworker] wrapMtpMessage ${JSON.stringify(object, 0, 2)} ${messageID} ${seqNo}`)

    return this.pushMessage(message, options)
}

MtpNetworker.prototype.wrapApiCall = function (method, params, options) {
    return new Promise((resolve, reject) => {
        const serializer = new TLSerialization(options)

        if (!this.connectionInited) {
            serializer.storeInt(0xda9b0d0d, 'invokeWithLayer')
            serializer.storeInt(Config.Schema.API.layer, 'layer')
            serializer.storeInt(0x69796de9, 'initConnection')
            serializer.storeInt(Config.App.id, 'api_id')
            serializer.storeString('Unknown UserAgent', 'device_model')
            serializer.storeString('Unknown Platform', 'system_version')
            serializer.storeString(Config.App.version, 'app_version')
            serializer.storeString('en', 'lang_code')
        }

        if (options.afterMessageID) {
            serializer.storeInt(0xcb9f372d, 'invokeAfterMsg')
            serializer.storeLong(options.afterMessageID, 'msg_id')
        }

        options.resultType = serializer.storeMethod(method, params)

        const messageID = MtpTimeManager.generateID()
        const seqNo = this.generateSeqNo()
        const message = {
            msg_id: messageID,
            seq_no: seqNo,
            body: serializer.getBytes(true),
            isAPI: true
        }

        LogService.logVerbose(`[MtpNetworker] wrapApiCall() ${method} ${JSON.stringify(params, 0, 2)} ${messageID} ${seqNo} ${JSON.stringify(options, 0, 2)}`)

        this.pushMessage(message, options)
            .then(res => resolve(res))
            .catch(err => reject(err))
    })
}

MtpNetworker.prototype.checkLongPoll = function (force) {
    var isClean = this.cleanupSent()
    if (this.longPollPending && tsNow() < this.longPollPending ||
        this.offline ||
        akStopped) {
        return false
    }
    var self = this
    Storage.get('dc').then(function (baseDcID) {
        if (isClean && (
            baseDcID != self.dcID ||
            self.upload ||
            self.sleepAfter && tsNow() > self.sleepAfter
        )) {
            return
        }
        self.sendLongPoll()
    })
}

MtpNetworker.prototype.sendLongPoll = function () {
    var maxWait = 25000
    var self = this

    this.longPollPending = tsNow() + maxWait

    this.wrapMtpCall('http_wait', {
        max_delay: 500,
        wait_after: 150,
        max_wait: maxWait
    }, {
            noResponse: true,
            longPoll: true
        }).then(function () {
            delete self.longPollPending
            self.checkLongPoll.bind(self)()
        }, function (error) {
            LogService.logError(`[MtpNetworker] sendLongPoll() ${new ErrorResponse(error)}`)
        })
}

MtpNetworker.prototype.pushMessage = function (message, options = {}) {
    return new Promise((resolve, reject) => {
        this.sentMessages[message.msg_id] = { ...message, ...options, deferred: { resolve, reject } }
        this.pendingMessages[message.msg_id] = 0

        if (!options || !options.noShedule) {
            this.sheduleRequest()
        }
        if (typeof options === 'object') {
            options.messageID = message.msg_id
        }
    })
}

MtpNetworker.prototype.pushResend = function (messageID, delay) {
    var value = delay ? tsNow() + delay : 0
    var sentMessage = this.sentMessages[messageID]
    if (sentMessage.container) {
        for (var i = 0; i < sentMessage.inner.length; i++) {
            this.pendingMessages[sentMessage.inner[i]] = value
        }
    } else {
        this.pendingMessages[messageID] = value
    }

    this.sheduleRequest(delay)
}

MtpNetworker.prototype.getMsgKey = function (dataWithPadding, isOut) {
    var authKey = this.authKeyUint8
    var x = isOut ? 0 : 8
    var msgKeyLargePlain = bufferConcat(authKey.subarray(88 + x, 88 + x + 32), dataWithPadding)
    const msgKeyLarge = sha256HashSync(msgKeyLargePlain)
    var msgKey = new Uint8Array(msgKeyLarge).subarray(8, 24)
    return msgKey
}

MtpNetworker.prototype.getAesKeyIv = function (msgKey, isOut) {
    var authKey = this.authKeyUint8
    var x = isOut ? 0 : 8
    var sha2aText = new Uint8Array(52)
    var sha2bText = new Uint8Array(52)
    var promises = {}

    sha2aText.set(msgKey, 0)
    sha2aText.set(authKey.subarray(x, x + 36), 16)
    let result_sha2a = sha256HashSync(sha2aText)

    sha2bText.set(authKey.subarray(40 + x, 40 + x + 36), 0)
    sha2bText.set(msgKey, 36)
    let result_sha2b = sha256HashSync(sha2bText)

    var aesKey = new Uint8Array(32)
    var aesIv = new Uint8Array(32)
    var sha2a = new Uint8Array(result_sha2a)
    var sha2b = new Uint8Array(result_sha2b)

    aesKey.set(sha2a.subarray(0, 8))
    aesKey.set(sha2b.subarray(8, 24), 8)
    aesKey.set(sha2a.subarray(24, 32), 24)

    aesIv.set(sha2b.subarray(0, 8))
    aesIv.set(sha2a.subarray(8, 24), 8)
    aesIv.set(sha2b.subarray(24, 32), 24)

    return [aesKey, aesIv]
}

MtpNetworker.prototype.checkConnection = function (event) {
    $rootScope.offlineConnecting = true

    LogService.logVerbose(`[MtpNetworker] checkConnection()`)
    //$timeout.cancel(this.checkConnectionPromise)

    var serializer = new TLSerialization({ mtproto: true })
    var pingID = [nextRandomInt(0xFFFFFFFF), nextRandomInt(0xFFFFFFFF)]

    serializer.storeMethod('ping', { ping_id: pingID })

    var pingMessage = {
        msg_id: MtpTimeManager.generateID(),
        seq_no: this.generateSeqNo(true),
        body: serializer.getBytes()
    }

    var self = this
    this.sendEncryptedRequest(pingMessage, { timeout: 15000 })
        .then(function (result) {
            /*delete $rootScope.offlineConnecting
            self.toggleOffline(false)
            */
        })
        .catch(function () {
            LogService.logVerbose(`[MtpNetworker] checkConnection() Delay ${self.checkConnectionPeriod * 1000}`)
            //self.checkConnectionPromise = $timeout(self.checkConnection.bind(self), parseInt(self.checkConnectionPeriod * 1000))
            self.checkConnectionPeriod = Math.min(60, self.checkConnectionPeriod * 1.5)
            /*
            $timeout(function () {
                delete $rootScope.offlineConnecting
            }, 1000)
            */
        })
}

MtpNetworker.prototype.toggleOffline = function (enabled) {
    LogService.logVerbose(`[MtpNetworker] toggleOffline() ${enabled}`)

    if (this.offline !== undefined && this.offline == enabled) {
        return false
    }

    this.offline = enabled
    //$rootScope.offline = enabled
    //$rootScope.offlineConnecting = false

    /*

    if (this.offline) {
        $timeout.cancel(this.nextReqPromise)
        delete this.nextReq

        if (this.checkConnectionPeriod < 1.5) {
            this.checkConnectionPeriod = 0
        }

        this.checkConnectionPromise = $timeout(this.checkConnection.bind(this), parseInt(this.checkConnectionPeriod * 1000))
        this.checkConnectionPeriod = Math.min(30, (1 + this.checkConnectionPeriod) * 1.5)

        this.onOnlineCb = this.checkConnection.bind(this)        
    } else {
        delete this.longPollPending
        this.checkLongPoll()
        this.sheduleRequest()
      
        $timeout.cancel(this.checkConnectionPromise)
    }
    */
}

MtpNetworker.prototype.performSheduledRequest = function () {
    LogService.logVerbose(`[MtpNetworker] performSheduledRequest()`)

    if (this.offline || akStopped) {
        LogService.logVerbose(`[MtpNetworker] performSheduledRequest() Cancel sheduled`)
        return false
    }

    delete this.nextReq

    if (this.pendingAcks.length) {
        var ackMsgIDs = []
        for (var i = 0; i < this.pendingAcks.length; i++) {
            ackMsgIDs.push(this.pendingAcks[i])
        }
        this.wrapMtpMessage({ _: 'msgs_ack', msg_ids: ackMsgIDs }, { notContentRelated: true, noShedule: true })
    }

    if (this.pendingResends.length) {
        var resendMsgIDs = []
        var resendOpts = { noShedule: true, notContentRelated: true }
        for (var i = 0; i < this.pendingResends.length; i++) {
            resendMsgIDs.push(this.pendingResends[i])
        }
        this.wrapMtpMessage({ _: 'msg_resend_req', msg_ids: resendMsgIDs }, resendOpts)
        this.lastResendReq = { req_msg_id: resendOpts.messageID, resend_msg_ids: resendMsgIDs }
    }

    let messages = []
    let message
    let messagesByteLen = 0
    let currentTime = tsNow()
    let hasApiCall = false
    let hasHttpWait = false
    let lengthOverflow = false
    let singlesCount = 0
    let self = this

    Object.keys(this.pendingMessages).forEach((messageID) => {
        const value = this.pendingMessages[messageID]

        if (!value || value >= currentTime) {
            if (message = self.sentMessages[messageID]) {
                var messageByteLength = (message.body.byteLength || message.body.length) + 32
                if (!message.notContentRelated &&
                    lengthOverflow) {
                    return
                }
                if (!message.notContentRelated &&
                    messagesByteLen &&
                    messagesByteLen + messageByteLength > 655360) { // 640 Kb
                    lengthOverflow = true
                    return
                }
                if (message.singleInRequest) {
                    singlesCount++
                    if (singlesCount > 1) {
                        return
                    }
                }
                messages.push(message)
                messagesByteLen += messageByteLength
                if (message.isAPI) {
                    hasApiCall = true
                }
                else if (message.longPoll) {
                    hasHttpWait = true
                }
            }
            delete self.pendingMessages[messageID]
        }
    })

    if (hasApiCall && !hasHttpWait) {
        var serializer = new TLSerialization({ mtproto: true })
        serializer.storeMethod('http_wait', {
            max_delay: 500,
            wait_after: 150,
            max_wait: 3000
        })
        messages.push({
            msg_id: MtpTimeManager.generateID(),
            seq_no: this.generateSeqNo(),
            body: serializer.getBytes()
        })
    }

    if (!messages.length) {
        return
    }

    var noResponseMsgs = []

    if (messages.length > 1) {
        var container = new TLSerialization({ mtproto: true, startMaxLength: messagesByteLen + 64 })
        container.storeInt(0x73f1f8dc, 'CONTAINER[id]')
        container.storeInt(messages.length, 'CONTAINER[count]')
        var onloads = []
        var innerMessages = []
        for (var i = 0; i < messages.length; i++) {
            container.storeLong(messages[i].msg_id, 'CONTAINER[' + i + '][msg_id]')
            innerMessages.push(messages[i].msg_id)
            container.storeInt(messages[i].seq_no, 'CONTAINER[' + i + '][seq_no]')
            container.storeInt(messages[i].body.length, 'CONTAINER[' + i + '][bytes]')
            container.storeRawBytes(messages[i].body, 'CONTAINER[' + i + '][body]')
            if (messages[i].noResponse) {
                noResponseMsgs.push(messages[i].msg_id)
            }
        }

        var containerSentMessage = {
            msg_id: MtpTimeManager.generateID(),
            seq_no: this.generateSeqNo(true),
            container: true,
            inner: innerMessages
        }

        message = { body: container.getBytes(true), ...containerSentMessage }

        this.sentMessages[message.msg_id] = containerSentMessage

        LogService.logVerbose(`[MtpNetworker] performSheduledRequest() Container ${JSON.stringify(innerMessages, 0, 2)} ${message.msg_id} ${message.seq_no}`)
    } else {
        if (message.noResponse) {
            noResponseMsgs.push(message.msg_id)
        }
        this.sentMessages[message.msg_id] = message
    }

    this.pendingAcks = []

    LogService.logVerbose(`[MtpNetworker] performSheduledRequest() sendEncryptedRequest(${JSON.stringify(message, 0, 2)})`)

    this.sendEncryptedRequest(message).then(function (result) {
        self.toggleOffline(false)

        const response = self.parseResponse(result.data)

        LogService.logVerbose(`[MtpNetworker] performSheduledRequest() sendEncryptedRequest() Server response ${self.dcID} ${JSON.stringify(response, 0, 2)}`)

        self.processMessage(response.response, response.messageID, response.sessionID)

        noResponseMsgs.forEach(function (msgID) {
            if (self.sentMessages[msgID]) {
                var deferred = self.sentMessages[msgID].deferred
                delete self.sentMessages[msgID]
                deferred.resolve()
            }
        })

        //self.checkLongPoll()

        self.checkConnectionPeriod = Math.max(1.1, Math.sqrt(self.checkConnectionPeriod))

    })
        .catch(error => {
            if (message.container) {
                message.inner.forEach(function (msgID) {
                    self.pendingMessages[msgID] = 0
                })
                delete self.sentMessages[message.msg_id]
            } else {
                self.pendingMessages[message.msg_id] = 0
            }

            noResponseMsgs.forEach(function (msgID) {
                if (self.sentMessages[msgID]) {
                    var deferred = self.sentMessages[msgID].deferred
                    delete self.sentMessages[msgID]
                    delete self.pendingMessages[msgID]
                    deferred.reject()
                }
            })

            self.toggleOffline(true)
        })

    /*
    if (lengthOverflow || singlesCount > 1) {
        this.sheduleRequest()
    }
    */
}

MtpNetworker.prototype.getEncryptedMessage = function (dataWithPadding) {
    var self = this
    const msgKey = self.getMsgKey(dataWithPadding, true)
    const keyIv = self.getAesKeyIv(msgKey, true)
    const encryptedBytes = aesEncryptSync(dataWithPadding, keyIv[0], keyIv[1])
    return {
        bytes: encryptedBytes,
        msgKey: msgKey
    }
}

MtpNetworker.prototype.getDecryptedMessage = function (msgKey, encryptedData) {
    const keyIv = this.getAesKeyIv(msgKey, false)
    return aesDecryptSync(encryptedData, keyIv[0], keyIv[1])
}

MtpNetworker.prototype.sendEncryptedRequest = function (message, options = {}) {
    return new Promise((resolve, reject) => {
        var self = this
        options = options || {}
        var data = new TLSerialization({ startMaxLength: message.body.length + 2048 })

        data.storeIntBytes(this.serverSalt, 64, 'salt')
        data.storeIntBytes(this.sessionID, 64, 'session_id')

        data.storeLong(message.msg_id, 'message_id')
        data.storeInt(message.seq_no, 'seq_no')

        data.storeInt(message.body.length, 'message_data_length')
        data.storeRawBytes(message.body, 'message_data')

        var dataBuffer = data.getBuffer()

        var paddingLength = (16 - (data.offset % 16)) + 16 * (1 + nextRandomInt(5))
        var padding = new Array(paddingLength)
        new SecureRandom().nextBytes(padding)

        var dataWithPadding = bufferConcat(dataBuffer, padding)

        const encryptedResult = this.getEncryptedMessage(dataWithPadding)

        var request = new TLSerialization({ startMaxLength: encryptedResult.bytes.byteLength + 256 })
        request.storeIntBytes(self.authKeyID, 64, 'auth_key_id')
        request.storeIntBytes(encryptedResult.msgKey, 128, 'msg_key')
        request.storeRawBytes(encryptedResult.bytes, 'encrypted_data')

        var requestData = request.getArray()

        var requestPromise
        var url = MtpDcConfigurator.chooseServer(self.dcID)
        var baseError = { code: 406, type: 'NETWORK_BAD_RESPONSE', url: url }

        networkRequest(url, requestData).then(
            function (result) {
                if (!result.data || !result.data.byteLength) {
                    reject(baseError)
                }
                resolve(result)
            })
            .catch(error => {
                if (!error.message && !error.type) {
                    error = { ...baseError, type: 'NETWORK_BAD_REQUEST', originalError: error }
                }
                LogService.logError(`[MtpNetworker] sendEncryptedRequest() ${error.message}`)
                reject(error)
            })
    })
}

export function toArrayBuffer(arr) {
    var ab = new ArrayBuffer(arr.length)
    var view = new Uint8Array(ab)
    for (var i = 0; i < arr.length; ++i) {
        view[i] = arr[i]
    }
    return ab
}

MtpNetworker.prototype.parseResponse = function (responseBuffer) {
    var self = this
    var deserializer = new TLDeserialization(responseBuffer)

    var authKeyID = deserializer.fetchIntBytes(64, false, 'auth_key_id')

    if (!bytesCmp(authKeyID, this.authKeyID)) {
        throw new Error('[MT] Invalid server auth_key_id: ' + bytesToHex(authKeyID))
    }
    var msgKey = deserializer.fetchIntBytes(128, true, 'msg_key')
    var encryptedData = deserializer.fetchRawBytes(responseBuffer.byteLength - deserializer.getOffset(), true, 'encrypted_data')

    const dataWithPadding = toArrayBuffer(self.getDecryptedMessage(msgKey, encryptedData))
    const calcMsgKey = self.getMsgKey(dataWithPadding, false)
    if (!bytesCmp(msgKey, calcMsgKey)) {
        LogService.logError(`[MtpNetworker] parseResponse() server msgKey mismatch: ${bytesFromArrayBuffer(calcMsgKey)}`)
        throw new Error('[MT] server msgKey mismatch')
    }

    var deserializer = new TLDeserialization(dataWithPadding, { mtproto: true })

    var salt = deserializer.fetchIntBytes(64, false, 'salt')
    var sessionID = deserializer.fetchIntBytes(64, false, 'session_id')
    var messageID = deserializer.fetchLong('message_id')

    if (!bytesCmp(sessionID, self.sessionID) &&
        (!self.prevSessionID || !bytesCmp(sessionID, self.prevSessionID))) {
        LogService.logError(`[MtpNetworker] parseResponse() Invalid server session_id: ${bytesToHex(sessionID)}`)
        throw new Error('[MT] Invalid server session_id: ' + bytesToHex(sessionID))
    }

    var seqNo = deserializer.fetchInt('seq_no')
    var totalLength = dataWithPadding.bytesLength

    var messageBodyLength = deserializer.fetchInt('message_data[length]')
    var offset = deserializer.getOffset()

    if ((messageBodyLength % 4 !== 0) || (messageBodyLength > totalLength - offset)) {
        throw new Error('[MT] Invalid body length: ' + messageBodyLength)
    }
    var messageBody = deserializer.fetchRawBytes(messageBodyLength, true, 'message_data')

    var offset = deserializer.getOffset()
    var paddingLength = totalLength - offset
    if (paddingLength < 12 || paddingLength > 1024) {
        throw new Error('[MT] Invalid padding length: ' + paddingLength)
    }

    var buffer = bytesToArrayBuffer(messageBody)
    var deserializerOptions = {
        mtproto: true,
        override: {
            mt_message: function (result, field) {
                result.msg_id = this.fetchLong(field + '[msg_id]')
                result.seqno = this.fetchInt(field + '[seqno]')
                result.bytes = this.fetchInt(field + '[bytes]')

                var offset = this.getOffset()

                try {
                    result.body = this.fetchObject('Object', field + '[body]')
                } catch (e) {
                    LogService.logError(`[MtpNetworker] parseResponse() parse error: ${new ErrorResponse(e)}`)
                    result.body = { _: 'parse_error', error: e }
                }
                if (this.offset != offset + result.bytes) {
                    this.offset = offset + result.bytes
                }
            },
            mt_rpc_result: function (result, field) {
                result.req_msg_id = this.fetchLong(field + '[req_msg_id]')

                var sentMessage = self.sentMessages[result.req_msg_id]
                var type = sentMessage && sentMessage.resultType || 'Object'

                if (result.req_msg_id && !sentMessage) {
                    return
                }
                result.result = this.fetchObject(type, field + '[result]')
            }
        }
    }
    var deserializer = new TLDeserialization(buffer, deserializerOptions)
    var response = deserializer.fetchObject('', 'INPUT')

    return {
        response: response,
        messageID: messageID,
        sessionID: sessionID,
        seqNo: seqNo
    }
}

MtpNetworker.prototype.applyServerSalt = function (newServerSalt) {
    var serverSalt = longToBytes(newServerSalt)

    const newNetworkers = getState().networkers
    let networker = newNetworkers.find(nw => nw.id == this.dcID)
    if (!networker) {
        throw new Error(`Networker with dcID = ${thid.dcID} not found in the state`)
    }

    networker.auth.serverSalt = serverSalt
    setState({ networkers: newNetworkers })
    this.serverSalt = serverSalt
    return true
}

MtpNetworker.prototype.sheduleRequest = function (delay) {
    if (this.offline) {
        this.checkConnection('forced shedule')
    }
    var nextReq = tsNow() + delay

    if (delay && this.nextReq && this.nextReq <= nextReq) {
        return false
    }

    /*
    $timeout.cancel(this.nextReqPromise)
    if (delay > 0) {
        this.nextReqPromise = $timeout(this.performSheduledRequest.bind(this), delay || 0)
    } else {
        setZeroTimeout(this.performSheduledRequest.bind(this))
    }
    */

    this.performSheduledRequest.bind(this)()
    this.nextReq = nextReq
}

MtpNetworker.prototype.ackMessage = function (msgID) {
    LogService.logVerbose(`[MtpNetworker] ackMessage() ${msgID}`)
    this.pendingAcks.push(msgID)
    this.sheduleRequest(30000)
}

MtpNetworker.prototype.reqResendMessage = function (msgID) {
    LogService.logVerbose(`[MtpNetworker] reqResendMessage() ${msgID}`)
    this.pendingResends.push(msgID)
    this.sheduleRequest(100)
}

MtpNetworker.prototype.cleanupSent = function () {
    var self = this
    var notEmpty = false

    Object.keys(this.sentMessages).forEach(function (msgID) {
        const message = self.sentMessages[msgID]
        if (message.notContentRelated && self.pendingMessages[msgID] === undefined) {
            delete self.sentMessages[msgID]
        }
        else if (message.container) {
            for (var i = 0; i < message.inner.length; i++) {
                if (self.sentMessages[message.inner[i]] !== undefined) {
                    notEmpty = true
                    return
                }
            }
            delete self.sentMessages[msgID]
        } else {
            notEmpty = true
        }
    })

    return !notEmpty
}

MtpNetworker.prototype.processMessageAck = function (messageID) {
    var sentMessage = this.sentMessages[messageID]
    if (sentMessage && !sentMessage.acked) {
        delete sentMessage.body
        sentMessage.acked = true

        return true
    }

    return false
}

MtpNetworker.prototype.processError = function (rawError) {
    var matches = (rawError.error_message || '').match(/^([A-Z_0-9]+\b)(: (.+))?/) || []
    rawError.error_code = uintToInt(rawError.error_code)

    return {
        code: !rawError.error_code || rawError.error_code <= 0 ? 500 : rawError.error_code,
        type: matches[1] || 'UNKNOWN',
        description: matches[3] || ('CODE#' + rawError.error_code + ' ' + rawError.error_message),
        originalError: rawError
    }
}

MtpNetworker.prototype.processMessage = function (message, messageID, sessionID) {
    var msgidInt = parseInt(messageID.toString(10).substr(0, -10), 10)
    if (msgidInt % 2) {
        LogService.logInfo(`[MtpNetworker] processMessage() Server even message id ${messageID}`)
        return
    }
    switch (message._) {
        case 'msg_container':
            var len = message.messages.length
            for (var i = 0; i < len; i++) {
                this.processMessage(message.messages[i], message.messages[i].msg_id, sessionID)
            }
            break

        case 'bad_server_salt':
            LogService.logInfo(`[MtpNetworker] processMessage() Bad server salt ${JSON.stringify(message, 0, 2)}`)
            var sentMessage = this.sentMessages[message.bad_msg_id]
            if (!sentMessage || sentMessage.seq_no != message.bad_msg_seqno) {
                LogService.logInfo(`[MtpNetworker] processMessage() Bad server salt for invalid message ${JSON.stringify(message, 0, 2)}`)
                throw new Error('[MT] Bad server salt for invalid message')
            }

            this.applyServerSalt(message.new_server_salt)
            this.pushResend(message.bad_msg_id)
            this.ackMessage(messageID)
            break

        case 'bad_msg_notification':
            LogService.logInfo(`[MtpNetworker] processMessage() Bad msg notification ${JSON.stringify(message, 0, 2)}`)
            var sentMessage = this.sentMessages[message.bad_msg_id]
            if (!sentMessage || sentMessage.seq_no != message.bad_msg_seqno) {
                throw new Error('[MT] Bad msg notification for invalid message')
            }

            if (message.error_code == 16 || message.error_code == 17) {
                if (MtpTimeManager.applyServerTime(
                    bigStringInt(messageID).shiftRight(32).toString(10)
                )) {
                    LogService.logInfo(`[MtpNetworker] processMessage() Update session`)
                    this.updateSessionId()
                }
                var badMessage = this.updateSentMessage(message.bad_msg_id)
                this.pushResend(badMessage.msg_id)
                this.ackMessage(messageID)
            }
            break

        case 'message':
            if (this.lastServerMessages.indexOf(messageID) != -1) {
                this.ackMessage(messageID)
                return
            }
            this.lastServerMessages.push(messageID)
            if (this.lastServerMessages.length > 100) {
                this.lastServerMessages.shift()
            }
            this.processMessage(message.body, message.msg_id, sessionID)
            break

        case 'new_session_created':
            this.ackMessage(messageID)

            this.processMessageAck(message.first_msg_id)
            this.applyServerSalt(message.server_salt)

            var self = this

            const currentDcId = getState().current_dc_id

            if (currentDcId == self.dcID && !self.upload && updatesProcessor) {
                updatesProcessor(message, true)
            }

            break

        case 'msgs_ack':
            for (var i = 0; i < message.msg_ids.length; i++) {
                this.processMessageAck(message.msg_ids[i])
            }
            break

        case 'msg_detailed_info':
            if (!this.sentMessages[message.msg_id]) {
                this.ackMessage(message.answer_msg_id)
                break
            }
        case 'msg_new_detailed_info':
            if (this.pendingAcks.indexOf(message.answer_msg_id)) {
                break
            }
            this.reqResendMessage(message.answer_msg_id)
            break

        case 'msgs_state_info':
            this.ackMessage(message.answer_msg_id)
            if (this.lastResendReq && this.lastResendReq.req_msg_id == message.req_msg_id && this.pendingResends.length) {
                var i, badMsgID, pos
                for (i = 0; i < this.lastResendReq.resend_msg_ids.length; i++) {
                    badMsgID = this.lastResendReq.resend_msg_ids[i]
                    pos = this.pendingResends.indexOf(badMsgID)
                    if (pos != -1) {
                        this.pendingResends.splice(pos, 1)
                    }
                }
            }
            break

        case 'rpc_result':
            this.ackMessage(messageID)

            var sentMessageID = message.req_msg_id
            var sentMessage = this.sentMessages[sentMessageID]

            this.processMessageAck(sentMessageID)
            if (sentMessage) {
                var deferred = sentMessage.deferred
                if (message.result._ == 'rpc_error') {
                    var error = this.processError(message.result)
                    LogService.logError(`[MtpNetworker] processMessageAck() Rpc error ${new ErrorResponse(error)}`)
                    if (deferred) {
                        deferred.reject(error)
                    }
                } else {
                    if (deferred) {
                        LogService.logVerbose(`[MtpNetworker] processMessageAck() Rpc response ${JSON.stringify(message.result, 0, 2)}`)
                        sentMessage.deferred.resolve(message.result)
                    }
                    if (sentMessage.isAPI) {
                        this.connectionInited = true
                    }
                }

                delete this.sentMessages[sentMessageID]
            }
            break

        default:
            this.ackMessage(messageID)

            if (updatesProcessor) {
                updatesProcessor(message, true)
            }
            break

    }
}

export function startAll() {
    if (akStopped) {
        akStopped = false
        updatesProcessor({ _: 'new_session_created' }, true)
    }
}

export function stopAll() {
    akStopped = true
}

export const getNetworker = function (dcID, authKey, serverSalt, options) {
    return new MtpNetworker(dcID, authKey, serverSalt, options)
}

export const setUpdatesProcessor = function (callback) {
    updatesProcessor = callback
}
