class ErrorResponse {
    constructor(obj) {
        this.dataObject = {}

        if (!obj) {
            return
        }

        if (obj instanceof Error) {
            Object.getOwnPropertyNames(obj).forEach((key) => this.dataObject[key] = obj[key])
            return
        }

        this.dataObject = obj
    }

    toJSON() {
        return this.dataObject
    }

    toString() {
        /// Circular Reference Exception
        let cache = []
        return JSON.stringify(this.dataObject, (key, value) => {
            if (typeof value === 'object' && value !== null) {
                if (cache.indexOf(value) !== -1) {
                    return
                }
                cache.push(value)
            }
            return value
        }, 2)
    }

}

export default ErrorResponse