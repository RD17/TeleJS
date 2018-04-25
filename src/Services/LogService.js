import moment from 'moment'
import * as DateTimeService from './DateTimeService'

const LEVELS = {
    debug: {
        level: 0,
        description: 'debug'
    },
    verbose: {
        level: 1,
        description: 'verbose'
    },
    info: {
        level: 2,
        description: 'info'
    },
    error: {
        level: 3,
        description: 'error'
    }
}
const DATETIME_FORMAT = DateTimeService.getDefaultDateTimeFormat()

let sourceName = null
let minLevel = null

export const init = (loggingSourceName, minLoggingLevel) => {
    if (!minLoggingLevel) {
        throw new Error(`Please specify minimal logging level, levels available: ${Object.keys(LEVELS)}`)
    }
    if (!loggingSourceName) {
        throw new Error(`Please specify source name`)
    }
    sourceName = loggingSourceName
    minLevel = LEVELS[minLoggingLevel]
    if (!minLevel) {
        throw new Error(`Could not find logging level ${minLoggingLevel}, levels available: ${Object.keys(LEVELS)}`)
    }
}

export const logDebug = (message) => {
    if (LEVELS.debug.level >= minLevel.level) {
        logMessage(LEVELS.debug, message)
    }
}
export const logVerbose = (message) => {
    if (LEVELS.verbose.level >= minLevel.level) {
        logMessage(LEVELS.verbose, message)
    }
}
export const logInfo = (message) => {
    if (LEVELS.info.level >= minLevel.level) {
        logMessage(LEVELS.info, message)
    }
}
export const logError = (message) => {
    if (LEVELS.error.level >= minLevel.level) {
        logMessage(LEVELS.error, message)
    }
}

const logMessage = (level, message) => {
    if (level == LEVELS.error) {
        console.error(composeMessage(level.description, message))
        return
    }

    console.log(composeMessage(level.description, message))
}

const composeMessage = (levelDescription, message) => {
    if (!sourceName) {
        throw new Error('LogService is not initialized!')
    }

    return `${moment().format(DATETIME_FORMAT)}: [${sourceName}] [${levelDescription}] ${message}`
}