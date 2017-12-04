/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(1);


/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * @file Paw Extension for generating Baidu BCE Authorization Signature
 * @author Letian Zhang <zhangletian@baidu.com>
 */

var BCEAuthDynamicValue = function () {
    function BCEAuthDynamicValue() {
        _classCallCheck(this, BCEAuthDynamicValue);
    }

    _createClass(BCEAuthDynamicValue, [{
        key: 'evaluate',
        value: function evaluate(context) {
            if (context.runtimeInfo.task != 'requestSend') {
                return '** signature is only generated during request send **';
            }

            var currentRequest = context.getCurrentRequest();
            var method = currentRequest.method;
            var canonicalUri = this.constructor.canonicalizeUrl(currentRequest);
            var canonicalQueryString = this.constructor.canonicalizeQuery(currentRequest);

            var _constructor$canonica = this.constructor.canonicalizeHeaders(currentRequest),
                canonicalHeaders = _constructor$canonica.canonicalHeaders,
                signedHeaders = _constructor$canonica.signedHeaders;

            var canonicalRequest = method + '\n' + canonicalUri + '\n' + canonicalQueryString + '\n' + canonicalHeaders;

            var timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
            var authStringPrefix = 'bce-auth-v1/' + this.accessKeyId + '/' + timestamp + '/1800';
            var signingKeyDV = new DynamicValue('com.luckymarmot.HMACDynamicValue', {
                'input': authStringPrefix,
                'key': this.secretAccessKey,
                'algorithm': 3, // SHA-256
                'encoding': 'Hexadecimal'
            });
            var signingKey = signingKeyDV.getEvaluatedString();

            var signatureDV = new DynamicValue('com.luckymarmot.HMACDynamicValue', {
                'input': canonicalRequest,
                'key': signingKey,
                'algorithm': 3, // SHA-256
                'encoding': 'Hexadecimal'
            });
            var signature = signatureDV.getEvaluatedString();

            var authorization = authStringPrefix + '/' + signedHeaders + '/' + signature;

            return authorization;
        }
    }], [{
        key: 'canonicalizeUrl',
        value: function canonicalizeUrl(request) {
            var urlDV = new DynamicValue('com.luckymarmot.RequestURLDynamicValue', {
                request: request.id,
                includeScheme: false,
                includeHost: false,
                includeParameters: false
            });
            var url = urlDV.getEvaluatedString();
            return this.normalizeString(decodeURIComponent(url)).replace(/%2F/g, '/');
        }
    }, {
        key: 'canonicalizeQuery',
        value: function canonicalizeQuery(request) {
            var _this = this;

            var params = request.getUrlParameters(false);
            var canonicalQueryString = [];

            Object.keys(params).forEach(function (key) {
                if (key.toLowerCase() === 'authorization') {
                    return;
                }
                var value = params[key] || '';
                canonicalQueryString.push(_this.normalizeString(key) + '=' + _this.normalizeString(value));
            });

            canonicalQueryString.sort();

            return canonicalQueryString.join('&');
        }
    }, {
        key: 'canonicalizeHeaders',
        value: function canonicalizeHeaders(request) {
            var _this2 = this;

            var headers = request.getHeaders(false);
            var canonicalHeaders = [];

            headers['Host'] = /^https?\:\/\/(([^:\/?#]*)(?:\:([0-9]+))?)/.exec(request.urlBase)[2];

            Object.keys(headers).forEach(function (key) {
                var value = _this2.trim(headers[key]);

                if (value == null || value === '') {
                    return;
                }

                key = key.toLowerCase();
                if (/^x\-bce\-/.test(key) || headersToSign[key] === true) {
                    canonicalHeaders.push(_this2.normalizeString(key) + ':' + _this2.normalizeString(value));
                }
            });

            canonicalHeaders.sort();

            var signedHeaders = [];
            canonicalHeaders.forEach(function (item) {
                signedHeaders.push(item.split(':')[0]);
            });

            return {
                canonicalHeaders: canonicalHeaders.join('\n'),
                signedHeaders: signedHeaders.join(';')
            };
        }
    }, {
        key: 'normalizeString',
        value: function normalizeString(str) {
            var result = encodeURIComponent(str);
            result = result.replace(/[!'\(\)\*]/g, function ($1) {
                return kEscapedMap[$1];
            });

            return result;
        }
    }, {
        key: 'trim',
        value: function trim(str) {
            return (str || '').replace(/^\s+|\s+$/g, '');
        }
    }]);

    return BCEAuthDynamicValue;
}();

Object.assign(BCEAuthDynamicValue, {
    identifier: 'com.baidu.PawExtensions.BCEAuthDynamicValue',
    title: 'BCE Authorization Signature',
    inputs: [InputField('accessKeyId', 'Access Key ID', 'String'), InputField('secretAccessKey', 'Secret Access Key', 'SecureValue')]
});

var kEscapedMap = {
    '!': '%21',
    '\'': '%27',
    '(': '%28',
    ')': '%29',
    '*': '%2A'
};

var headersToSign = {
    'host': true,
    'content-length': true,
    'content-type': true,
    'content-md5': true
};

registerDynamicValueClass(BCEAuthDynamicValue);

/***/ })
/******/ ]);