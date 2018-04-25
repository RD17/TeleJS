import moment from 'moment'

const DATETIME_FORMAT = 'YYYY-MM-DD HH:mm:ss.SSS'

export const getDefaultDateTimeFormat = () => DATETIME_FORMAT

export const dateStrToDMY = (dateObject, format = 'DD.MM.YYYY') => {
    if (!dateObject) {
        throw new Error('Empty dateObject')
    }

    const date = moment(dateObject, format)

    return {
        day: date.date(),
        month: date.month() + 1,
        year: date.year()
    }
}

export const now = () => moment().format(DATETIME_FORMAT)

export const DMYToMomentDate = (date) => {
    return moment({ day: date.day, month: date.month - 1, year: date.year })
}