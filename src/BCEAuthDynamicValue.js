/**
 * @file Paw Extension for generating Baidu BCE Authorization Signature
 * @author Letian Zhang <zhangletian@baidu.com>
 */

class BCEAuthDynamicValue {
    evaluate(context) {
        if (context.runtimeInfo.task != 'requestSend') {
            return '** signature is only generated during request send **'
        }

        const currentRequest = context.getCurrentRequest()
        const method = currentRequest.method
        const canonicalUri = this.constructor.canonicalizeUrl(currentRequest)
        const canonicalQueryString = this.constructor.canonicalizeQuery(currentRequest)
        const { canonicalHeaders, signedHeaders } = this.constructor.canonicalizeHeaders(currentRequest)

        const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}`

        const timestamp = (new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z')
        const authStringPrefix = `bce-auth-v1/${this.accessKeyId}/${timestamp}/1800`
        const signingKeyDV = new DynamicValue('com.luckymarmot.HMACDynamicValue', {
            'input': authStringPrefix,
            'key': this.secretAccessKey,
            'algorithm': 3,  // SHA-256
            'encoding': 'Hexadecimal'
        })
        const signingKey = signingKeyDV.getEvaluatedString()

        const signatureDV = new DynamicValue('com.luckymarmot.HMACDynamicValue', {
            'input': canonicalRequest,
            'key': signingKey,
            'algorithm': 3,  // SHA-256
            'encoding': 'Hexadecimal'
        })
        const signature = signatureDV.getEvaluatedString()

        const authorization = `${authStringPrefix}/${signedHeaders}/${signature}`

        return authorization
    }

    static canonicalizeUrl(request) {
        const urlDV = new DynamicValue('com.luckymarmot.RequestURLDynamicValue', {
            request: request.id,
            includeScheme: false,
            includeHost: false,
            includeParameters: false
        })
        const url = urlDV.getEvaluatedString()
        return this.normalizeString(decodeURIComponent(url)).replace(/%2F/g, '/')
    }

    static canonicalizeQuery(request) {
        const params = request.getUrlParameters(false)
        const canonicalQueryString = []

        Object.keys(params).forEach(key => {
            if (key.toLowerCase() === 'authorization') {
                return
            }
            const value = params[key] || ''
            canonicalQueryString.push(this.normalizeString(key) + '=' + this.normalizeString(value))
        })

        canonicalQueryString.sort()

        return canonicalQueryString.join('&')
    }

    static canonicalizeHeaders(request) {
        const headers = request.getHeaders(false)
        const canonicalHeaders = []

        headers['Host'] = /^https?\:\/\/(([^:\/?#]*)(?:\:([0-9]+))?)/.exec(request.urlBase)[1]

        Object.keys(headers).forEach(key => {
            const value = this.trim(headers[key])

            if (value == null || value === '') {
                return
            }

            key = key.toLowerCase()
            if (/^x\-bce\-/.test(key) || headersToSign[key] === true) {
                canonicalHeaders.push(this.normalizeString(key) + ':' + this.normalizeString(value))
            }
        })

        canonicalHeaders.sort()

        var signedHeaders = []
        canonicalHeaders.forEach(item => {
            signedHeaders.push(item.split(':')[0])
        })

        return {
            canonicalHeaders: canonicalHeaders.join('\n'),
            signedHeaders: signedHeaders.join(';')
        }
    }

    static normalizeString(str) {
        var result = encodeURIComponent(str)
        result = result.replace(/[!'\(\)\*]/g, function ($1) {
            return kEscapedMap[$1]
        })

        return result
    }

    static trim(str) {
        return (str || '').replace(/^\s+|\s+$/g, '')
    }

}


Object.assign(BCEAuthDynamicValue, {
    identifier: 'com.baidu.PawExtensions.BCEAuthDynamicValue',
    title: 'BCE Authorization Signature',
    inputs: [
        InputField('accessKeyId', 'Access Key ID', 'String'),
        InputField('secretAccessKey', 'Secret Access Key', 'SecureValue'),
    ]
})

const kEscapedMap = {
    '!': '%21',
    '\'': '%27',
    '(': '%28',
    ')': '%29',
    '*': '%2A'
}

const headersToSign = {
    'host': true,
    'content-length': true,
    'content-type': true,
    'content-md5': true,
}

registerDynamicValueClass(BCEAuthDynamicValue)
