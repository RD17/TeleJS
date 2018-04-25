import Config from './config.js'
import { LogService, ErrorResponse } from './Services'

const defaultState = {
    current_dc_id: 2,
    prev_dc_id: undefined,
    dc_options: Config.Modes.test
        ? [
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 1,
                "ip_address": "149.154.175.10",
                "port": 80
            },
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 2,
                "ip_address": "149.154.167.40",
                "port": 80
            },
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 2,
                "ip_address": "149.154.175.117",
                "port": 80
            },
        ]
        : [
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 1,
                "ip_address": "149.154.175.50",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "ipv6": true
                },
                "flags": 1,
                "id": 1,
                "ip_address": "2001:0b28:f23d:f001:0000:0000:0000:000a",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 2,
                "ip_address": "149.154.167.51",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "static": true
                },
                "flags": 16,
                "id": 2,
                "ip_address": "149.154.167.51",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "ipv6": true
                },
                "flags": 1,
                "id": 2,
                "ip_address": "2001:067c:04e8:f002:0000:0000:0000:000a",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 3,
                "ip_address": "149.154.175.100",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "ipv6": true
                },
                "flags": 1,
                "id": 3,
                "ip_address": "2001:0b28:f23d:f003:0000:0000:0000:000a",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 4,
                "ip_address": "149.154.167.92",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "ipv6": true
                },
                "flags": 1,
                "id": 4,
                "ip_address": "2001:067c:04e8:f004:0000:0000:0000:000a",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "media_only": true
                },
                "flags": 2,
                "id": 4,
                "ip_address": "149.154.165.120",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {},
                "flags": 0,
                "id": 5,
                "ip_address": "91.108.56.170",
                "port": 443
            },
            {
                "_": "dcOption",
                "pFlags": {
                    "ipv6": true
                },
                "flags": 1,
                "id": 5,
                "ip_address": "2001:0b28:f23f:f005:0000:0000:0000:000a",
                "port": 443
            }
        ],
    networkers: [
    ]
}

let state = { ...defaultState }

let dump = undefined
let load = undefined

export const initState = (dumpState, loadState) => new Promise((resolve, reject) => {
    dump = dumpState
    load = loadState

    LogService.logInfo(`[state] init`)

    if (load) {
        load()
            .then(stateContents => {
                state = JSON.parse(stateContents)
                resolve()
            })
            .catch(err => {
                LogService.logError(`[state] ${new ErrorResponse(err)}`)

                reject()
            })
        return
    }

    resolve()
})

export const getState = () => {
    return state
}
export const setState = (newState) => {
    LogService.logVerbose(`[state] SetState()`)
    
    state = { ...state, ...newState }
    if (dump) {
        dump(JSON.stringify(state))
    }
}
