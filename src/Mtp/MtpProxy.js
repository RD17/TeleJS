import * as MtpAuthorizer from './MtpAuthorizer'
import * as MtpNetworker from './MtpNetworker'
import { getState, setState, initState } from '../state'
import { dT, tsNow } from '../Utils'
import { LogService, ErrorResponse } from '../Services'
import { name } from '../../package.json'

let isInitialized = false

export const init = (dumpState, loadState, loggingLevel = 'verbose') => new Promise((resolve, reject) => {
    LogService.init(name, loggingLevel)

    initState(dumpState, loadState)
        .then(() => {
            isInitialized = true
            resolve()
        })
        .catch(reject)
})

export const mtpGetNetworker = (dcId, options = {}) => new Promise((resolve, reject) => {
    if (!isInitialized) {
        reject(new Error('Not initialized!'))
        return
    }

    if (!dcId) {
        reject(new Error('Please specify dcId'))
        return
    }

    const networkerDataFromState = getState().networkers.find(nw => nw.id == dcId)
    if (networkerDataFromState) {
        const networker = MtpNetworker.getNetworker(dcId, networkerDataFromState.auth.authKey, networkerDataFromState.auth.serverSalt, options)
        resolve(networker)
        return
    }

    MtpAuthorizer.auth(dcId)
        .then((auth) => {
            const networker = MtpNetworker.getNetworker(dcId, auth.authKey, auth.serverSalt, options)
            setState({ networkers: [...getState().networkers, { id: dcId, auth: auth }] })
            resolve(networker)
        })
        .catch((error) => reject(error))
})

export const signUpUser = (phoneNumber, firstName, lastName, codeInputPromise) => new Promise((resolve, reject) => {
    if (!isInitialized) {
        reject(new Error('Not initialized!'))
        return
    }

    const sendCodeCallParams = {
        flags: 0,
        allow_flashcall: null,
        phone_number: phoneNumber,
        current_number: null,
        api_id: 2496,
        api_hash: '8da85b0d5bfe62527e5b244c209159c3'
    }

    mtpInvokeApi("auth.sendCode", sendCodeCallParams)
        .then(res => res.phone_code_hash)
        .then(phone_code_hash => {
            return codeInputPromise()
                .then((code) => {
                    return { code, phone_code_hash }
                })
        })
        .then(({ code, phone_code_hash }) => {
            const signUpCallParams = {
                phone_number: phoneNumber,
                phone_code_hash: phone_code_hash,
                phone_code: code,
                first_name: firstName,
                last_name: lastName
            }

            return mtpInvokeApi("auth.signUp", signUpCallParams)
        })
        .then(resolve)
        .catch(reject)
})

export const signInUser = (phoneNumber, codeInputPromise) => new Promise((resolve, reject) => {
    if (!isInitialized) {
        reject(new Error('Not initialized!'))
        return
    }

    const sendCodeCallParams = {
        sms_type: 5,
        phone_number: phoneNumber,
        api_id: 2496,
        api_hash: '8da85b0d5bfe62527e5b244c209159c3'
    }

    mtpInvokeApi("auth.sendCode", sendCodeCallParams)
        .then(res => res.phone_code_hash)
        .then(phone_code_hash => {
            return codeInputPromise()
                .then((code) => {
                    return { code, phone_code_hash }
                })
        })
        .then(({ code, phone_code_hash }) => {
            const signInCallParams = {
                phone_number: phoneNumber,
                phone_code_hash: phone_code_hash,
                phone_code: code
            }

            return mtpInvokeApi("auth.signIn", signInCallParams)
        })
        .then(resolve)
        .catch(reject)
})

export const mtpInvokeApi = (method, params, options = {}) => new Promise((resolve, reject) => {
    if (!isInitialized) {
        reject(new Error('Not initialized!'))
        return
    }

    LogService.logVerbose(`[MtpProxy] mtpInvokeApi() ${JSON.stringify(method, 0, 2)} ${JSON.stringify(params, 0, 2)} ${JSON.stringify(options, 0, 2)}`)

    const rejectPromise = function (error) {
        if (!error) {
            error = { type: 'ERROR_EMPTY' }
        } else if (typeof (error) !== 'object') {
            error = { message: error }
        }

        if (error.code == 406) {
            error.handled = true
        }

        reject(error)
    }

    const requestPromise = function (networker) {
        let dcId = networker.getDcId()
        let prevDcId = getState().prev_dc_id

        return networker.wrapApiCall(method, params, options)
            .then(resolve)
            .catch(error => {
                LogService.logError(`[MtpProxy] networker.wrapApiCall() ${new ErrorResponse(error)} ${prevDcId} ${dcId}`)

                if (error.code == 401 && (!prevDcId || (dcId == prevDcId))) {
                    rejectPromise(error)
                }
                else if (error.code == 401 && prevDcId && dcId != prevDcId) {
                    mtpInvokeApi('auth.exportAuthorization', { dc_id: dcId }, { dcId: prevDcId, noErrorBox: true })
                        .then((exportedAuth) =>
                            mtpInvokeApi('auth.importAuthorization', { id: exportedAuth.id, bytes: exportedAuth.bytes }, { dcId: dcId, noErrorBox: true })
                        )
                        .then(() => mtpInvokeApi(method, params, options))
                        .then(resolve)
                        .catch(rejectPromise)
                }
                else if (error.code == 303) {
                    var newDcID = error.type.match(/^(PHONE_MIGRATE_|NETWORK_MIGRATE_|USER_MIGRATE_)(\d+)/)[2]
                    if (newDcID != dcId) {
                        setState({ prev_dc_id: dcId, current_dc_id: newDcID })

                        mtpInvokeApi(method, params, options)
                            .then(resolve)
                            .catch(rejectPromise)
                    }
                }
                else if (!options.rawError && error.code == 420) {
                    const waitTime = error.type.match(/^FLOOD_WAIT_(\d+)/)[1] || 10
                    if (waitTime > (options.timeout || 60)) {
                        rejectPromise(error)
                        return
                    }

                    setTimeout(function () {
                        requestPromise(networker)
                    }, waitTime * 1000)
                }
                else if (!options.rawError && (error.code == 500 || error.type == 'MSG_WAIT_FAILED')) {
                    const now = tsNow()
                    if (options.stopTime) {
                        if (now >= options.stopTime) {
                            rejectPromise(error)
                            return
                        }
                    } else {
                        options.stopTime = now + (options.timeout !== undefined ? options.timeout : 10) * 1000
                    }
                    options.waitTime = options.waitTime ? Math.min(60, options.waitTime * 1.5) : 1
                    setTimeout(function () {
                        requestPromise(networker)
                    }, options.waitTime * 1000)
                } else {
                    rejectPromise(error)
                }
            })
    }

    const currrentDcId = options.dcId || getState().current_dc_id
    mtpGetNetworker(currrentDcId, options)
        .then(requestPromise)
        .catch(rejectPromise)
})