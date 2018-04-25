import { tsNow, dT, nextRandomInt, longFromInts } from '../Utils'
import { getState, setState } from '../state'
import { LogService, ErrorResponse } from '../Services'

let lastMessageID = [0, 0]
let timeOffset = 0

const to = getState().server_time_offset

if (to) {
    timeOffset = to
}

function generateMessageID() {
    var timeTicks = tsNow(),
        timeSec = Math.floor(timeTicks / 1000) + timeOffset,
        timeMSec = timeTicks % 1000,
        random = nextRandomInt(0xFFFF)

    var messageID = [timeSec, (timeMSec << 21) | (random << 3) | 4]
    if (lastMessageID[0] > messageID[0] ||
        lastMessageID[0] == messageID[0] && lastMessageID[1] >= messageID[1]) {
        messageID = [lastMessageID[0], lastMessageID[1] + 4]
    }

    lastMessageID = messageID

    return longFromInts(messageID[0], messageID[1])
}

export function applyServerTime(serverTime, localTime) {
    const newTimeOffset = serverTime - Math.floor((localTime || tsNow()) / 1000)
    const changed = Math.abs(timeOffset - newTimeOffset) > 10

    setState({ server_time_offset: newTimeOffset })

    lastMessageID = [0, 0]
    timeOffset = newTimeOffset

    return changed
}

export const generateID = generateMessageID


