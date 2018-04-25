import axios from 'axios'

export function toArrayBuffer(buf) {
    var ab = new ArrayBuffer(buf.length)
    var view = new Uint8Array(ab)
    for (var i = 0; i < buf.length; ++i) {
        view[i] = buf[i]
    }
    return ab
}

export const networkRequest = (url, requestData) => {
    return axios({
        method: 'POST',
        url: url,
        data: requestData,
        responseType: 'arraybuffer',
        transformRequest: null,
        transformResponse: (data) => toArrayBuffer(data)
    })
}