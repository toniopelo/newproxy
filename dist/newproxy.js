'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var chalk = require('chalk');
var forge = require('node-forge');
var mkdirp = require('mkdirp');
var path = require('path');
var fs = require('fs');
var Debug = require('debug');
var http = require('http');
var https = require('https');
var url = require('url');
var AgentKeepAlive = require('agentkeepalive');
var HashCode = require('ts-hashcode');
var NodeCache = require('node-cache');
var net = require('net');
var tls = require('tls');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var chalk__default = /*#__PURE__*/_interopDefaultLegacy(chalk);
var forge__default = /*#__PURE__*/_interopDefaultLegacy(forge);
var mkdirp__default = /*#__PURE__*/_interopDefaultLegacy(mkdirp);
var path__default = /*#__PURE__*/_interopDefaultLegacy(path);
var fs__default = /*#__PURE__*/_interopDefaultLegacy(fs);
var Debug__default = /*#__PURE__*/_interopDefaultLegacy(Debug);
var http__default = /*#__PURE__*/_interopDefaultLegacy(http);
var https__default = /*#__PURE__*/_interopDefaultLegacy(https);
var url__default = /*#__PURE__*/_interopDefaultLegacy(url);
var AgentKeepAlive__default = /*#__PURE__*/_interopDefaultLegacy(AgentKeepAlive);
var HashCode__default = /*#__PURE__*/_interopDefaultLegacy(HashCode);
var NodeCache__default = /*#__PURE__*/_interopDefaultLegacy(NodeCache);
var net__default = /*#__PURE__*/_interopDefaultLegacy(net);
var tls__default = /*#__PURE__*/_interopDefaultLegacy(tls);

class CaConfig {
    constructor() {
        this.caCertFileName = 'newproxy.ca.crt';
        this.caKeyFileName = 'newproxy.ca.key.pem';
        this.caName = 'NewProxy CA';
    }
    // eslint-disable-next-line class-methods-use-this
    getDefaultCABasePath() {
        const userHome = process.env.HOME || process.env.USERPROFILE || '';
        return path__default["default"].resolve(userHome, './newproxy');
    }
    getDefaultCACertPath() {
        return path__default["default"].resolve(this.getDefaultCABasePath(), this.caCertFileName);
    }
    getDefaultCaKeyPath() {
        return path__default["default"].resolve(this.getDefaultCABasePath(), this.caKeyFileName);
    }
}
const caConfig = new CaConfig();

class TlsUtils {
    static createCA(commonName) {
        const keys = forge__default["default"].pki.rsa.generateKeyPair(2048);
        const cert = forge__default["default"].pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = `${new Date().getTime()}`;
        cert.validity.notBefore = new Date();
        cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 5);
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 20);
        const attrs = [
            {
                name: 'commonName',
                value: commonName,
            },
            {
                name: 'countryName',
                value: 'RU',
            },
            {
                shortName: 'ST',
                value: 'Moscow',
            },
            {
                name: 'localityName',
                value: 'Moscow',
            },
            {
                name: 'organizationName',
                value: 'NewProxy',
            },
            {
                shortName: 'OU',
                value: 'https://github.com/sannysoft/newproxy',
            },
        ];
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.setExtensions([
            {
                name: 'basicConstraints',
                critical: true,
                cA: true,
            },
            {
                name: 'keyUsage',
                critical: true,
                keyCertSign: true,
            },
            {
                name: 'subjectKeyIdentifier',
            },
        ]);
        // self-sign certificate
        cert.sign(keys.privateKey, forge__default["default"].md.sha256.create());
        return {
            key: keys.privateKey,
            cert: cert,
        };
    }
    static covertNodeCertToForgeCert(originCertificate) {
        const obj = forge__default["default"].asn1.fromDer(originCertificate.raw.toString('binary'));
        return forge__default["default"].pki.certificateFromAsn1(obj);
    }
    static createFakeCertificateByDomain(caPair, domain) {
        const keys = forge__default["default"].pki.rsa.generateKeyPair(2048);
        const cert = forge__default["default"].pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = `${new Date().getTime()}`;
        cert.validity.notBefore = new Date();
        cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 1);
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
        const attrs = [
            {
                name: 'commonName',
                value: domain,
            },
            {
                name: 'countryName',
                value: 'RU',
            },
            {
                shortName: 'ST',
                value: 'Moscow',
            },
            {
                name: 'localityName',
                value: 'Moscow',
            },
            {
                name: 'organizationName',
                value: 'NewProxy',
            },
            {
                shortName: 'OU',
                value: 'https://github.com/sannysoft/newproxy',
            },
        ];
        cert.setIssuer(caPair.cert.subject.attributes);
        cert.setSubject(attrs);
        cert.setExtensions([
            {
                name: 'basicConstraints',
                critical: true,
                cA: false,
            },
            {
                name: 'keyUsage',
                critical: true,
                digitalSignature: true,
                contentCommitment: true,
                keyEncipherment: true,
                dataEncipherment: true,
                keyAgreement: true,
                keyCertSign: true,
                cRLSign: true,
                encipherOnly: true,
                decipherOnly: true,
            },
            {
                name: 'subjectAltName',
                altNames: [
                    {
                        type: 2,
                        value: domain,
                    },
                ],
            },
            {
                name: 'subjectKeyIdentifier',
            },
            {
                name: 'extKeyUsage',
                serverAuth: true,
                clientAuth: true,
                codeSigning: true,
                emailProtection: true,
                timeStamping: true,
            },
            {
                name: 'authorityKeyIdentifier',
            },
        ]);
        cert.sign(caPair.key, forge__default["default"].md.sha256.create());
        return {
            key: keys.privateKey,
            cert: cert,
        };
    }
    static createFakeCertificateByCA(caPair, originCertificate) {
        // const certificate = TlsUtils.covertNodeCertToForgeCert(originCertificate);
        const keys = forge__default["default"].pki.rsa.generateKeyPair(2048);
        const cert = forge__default["default"].pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = originCertificate.serialNumber;
        cert.validity.notBefore = new Date();
        cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 1);
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
        const attrs = [];
        Object.entries(originCertificate.subject).forEach(([name, value]) => {
            attrs.push({
                shortName: name,
                value: value,
            });
        });
        cert.setSubject(attrs);
        cert.setIssuer(caPair.cert.subject.attributes);
        const subjectAltNames = originCertificate.subjectaltname.split(', ').map((name) => ({
            // 2 is DNS type
            type: 2,
            value: name.replace('DNS:', '').trim(),
        }));
        cert.setExtensions([
            {
                name: 'basicConstraints',
                critical: true,
                cA: false,
            },
            {
                name: 'keyUsage',
                critical: true,
                digitalSignature: true,
                contentCommitment: true,
                keyEncipherment: true,
                dataEncipherment: true,
                keyAgreement: true,
                keyCertSign: true,
                cRLSign: true,
                encipherOnly: true,
                decipherOnly: true,
            },
            {
                name: 'subjectAltName',
                altNames: subjectAltNames,
            },
            {
                name: 'subjectKeyIdentifier',
            },
            {
                name: 'extKeyUsage',
                serverAuth: true,
                clientAuth: true,
                codeSigning: true,
                emailProtection: true,
                timeStamping: true,
            },
            {
                name: 'authorityKeyIdentifier',
            },
        ]);
        cert.sign(caPair.key, forge__default["default"].md.sha256.create());
        return {
            key: keys.privateKey,
            cert: cert,
        };
    }
    static isBrowserRequest(userAgent) {
        return /mozilla/i.test(userAgent);
    }
    static isMappingHostName(DNSName, hostname) {
        let reg = DNSName.replace(/\./g, '\\.').replace(/\*/g, '[^.]+');
        reg = `^${reg}$`;
        return new RegExp(reg).test(hostname);
    }
    static getMappingHostNamesFormCert(cert) {
        var _a, _b, _c, _d;
        let mappingHostNames = [(_b = (_a = cert.subject.getField('CN')) === null || _a === void 0 ? void 0 : _a.value) !== null && _b !== void 0 ? _b : []];
        // @ts-ignore
        const altNames = (_d = (_c = cert.getExtension('subjectAltName')) === null || _c === void 0 ? void 0 : _c.altNames) !== null && _d !== void 0 ? _d : [];
        mappingHostNames = mappingHostNames.concat(altNames.map((item) => item.value));
        return mappingHostNames;
    }
    static initCA(basePath) {
        const caCertPath = path__default["default"].resolve(basePath, caConfig.caCertFileName);
        const caKeyPath = path__default["default"].resolve(basePath, caConfig.caKeyFileName);
        try {
            fs__default["default"].accessSync(caCertPath, fs__default["default"].constants.F_OK);
            fs__default["default"].accessSync(caKeyPath, fs__default["default"].constants.F_OK);
            // has exist
            return {
                caCertPath: caCertPath,
                caKeyPath: caKeyPath,
                create: false,
            };
        }
        catch {
            const caObj = TlsUtils.createCA(caConfig.caName);
            const caCert = caObj.cert;
            const cakey = caObj.key;
            const certPem = forge__default["default"].pki.certificateToPem(caCert);
            const keyPem = forge__default["default"].pki.privateKeyToPem(cakey);
            mkdirp__default["default"].sync(path__default["default"].dirname(caCertPath));
            fs__default["default"].writeFileSync(caCertPath, certPem);
            fs__default["default"].writeFileSync(caKeyPath, keyPem);
        }
        return {
            caCertPath: caCertPath,
            caKeyPath: caKeyPath,
            create: true,
        };
    }
}

const logger$1 = Debug__default["default"]('newproxy');
class Logger {
    constructor(loggerConfig = false, errorLoggerConfig = false) {
        this.loggerConfig = loggerConfig;
        this.errorLoggerConfig = errorLoggerConfig;
    }
    log(message, colorFn) {
        var _a;
        if (typeof this.loggerConfig === 'function') {
            this.loggerConfig(message);
        }
        else if (this.loggerConfig) {
            const formattedMessage = (_a = colorFn === null || colorFn === void 0 ? void 0 : colorFn(message)) !== null && _a !== void 0 ? _a : message;
            logger$1(formattedMessage);
        }
    }
    logError(message, comment) {
        if (typeof this.errorLoggerConfig === 'function') {
            this.errorLoggerConfig(message, comment);
        }
        else if (this.loggerConfig) {
            if (message instanceof Error) {
                this.log(message.message);
            }
            else {
                this.log(message, chalk__default["default"].red);
            }
        }
    }
}

function makeErr(message) {
    throw new Error(message);
}
function isNullOrUndefined(obj) {
    return typeof obj === 'undefined' || obj === null;
}

function types(value) {
    return value !== null && typeof value === 'object';
}
function isString(value) {
    return typeof value === 'string';
}
function isPresent(value) {
    return value !== undefined && value !== null;
}

function isExternalProxyConfigObject(obj) {
    return types(obj) && !!obj.host && !!obj.port;
}
class ExternalProxyHelper {
    constructor(config) {
        this.config = config;
    }
    getUrlObject() {
        let proxy;
        proxy = isString(this.config) ? this.config : `${this.config.host}:${this.config.port}`;
        if (!proxy.startsWith('http:') && !proxy.startsWith('https:'))
            proxy = `http://${proxy}`;
        return url__default["default"].parse(proxy);
    }
    getProtocol() {
        return this.getUrlObject().protocol || '';
    }
    getLoginAndPassword() {
        var _a;
        if (typeof this.config === 'string') {
            const auth = (_a = this.getUrlObject()) === null || _a === void 0 ? void 0 : _a.auth;
            return auth || undefined;
        }
        if (isNullOrUndefined(this.config.username) || isNullOrUndefined(this.config.password))
            return undefined;
        return `${this.config.username}:${this.config.password}`;
    }
    getBasicAuth() {
        const authString = this.getLoginAndPassword();
        if (!authString)
            return undefined;
        return Buffer.from(authString).toString('base64');
    }
    getConfigObject() {
        var _a, _b, _c, _d;
        if (isExternalProxyConfigObject(this.config)) {
            return this.config;
        }
        const proxyUrl = this.getUrlObject();
        const [login, password] = (_b = (_a = this.getLoginAndPassword()) === null || _a === void 0 ? void 0 : _a.split(':')) !== null && _b !== void 0 ? _b : [undefined, undefined];
        return {
            host: (_c = proxyUrl.host) !== null && _c !== void 0 ? _c : makeErr('No host set for proxy'),
            port: Number.parseInt((_d = proxyUrl.port) !== null && _d !== void 0 ? _d : makeErr('No port set for proxy'), 10),
            username: login,
            password: password,
        };
    }
}

const contexts = {};

const TunnelAgent = require('@postman/tunnel-agent');
const myCache = new NodeCache__default["default"]({ stdTTL: 15 * 60, checkperiod: 60, useClones: false });
class TunnelingAgent {
    static getTunnelAgent(isSsl, externalProxyHelper) {
        var _a;
        const urlObject = externalProxyHelper.getUrlObject();
        const externalProxyProtocol = urlObject.protocol || 'http:';
        const port = Number((_a = urlObject === null || urlObject === void 0 ? void 0 : urlObject.port) !== null && _a !== void 0 ? _a : (externalProxyProtocol === 'http:' ? 80 : 443));
        const hostname = urlObject.hostname || 'localhost';
        const tunnelConfig = {
            proxy: {
                host: hostname,
                port: port,
            },
        };
        const auth = externalProxyHelper.getLoginAndPassword();
        if (auth) {
            // @ts-ignore
            tunnelConfig.proxy.proxyAuth = auth;
        }
        const externalProxyHostCache = (isSsl ? '1' : '0') + externalProxyProtocol + HashCode__default["default"](tunnelConfig);
        const cachedTunnel = myCache.get(externalProxyHostCache);
        if (cachedTunnel)
            return cachedTunnel;
        const newTunnel = this.getNewTunnel(isSsl, externalProxyProtocol, tunnelConfig);
        myCache.set(externalProxyHostCache, newTunnel, 15 * 60 * 1000 /* 15 minutes */);
        return newTunnel;
    }
    static getNewTunnel(isSsl, externalProxyProtocol, tunnelConfig) {
        if (isSsl) {
            if (externalProxyProtocol === 'http:') {
                return TunnelAgent.httpsOverHttp(tunnelConfig);
            }
            return TunnelAgent.httpsOverHttps(tunnelConfig);
        }
        if (externalProxyProtocol === 'http:') {
            // if (!httpOverHttpAgent) {
            //     httpOverHttpAgent = tunnelAgent.httpOverHttp(tunnelConfig);
            // }
            return false;
        }
        return TunnelAgent.httpOverHttps(tunnelConfig);
    }
}

const httpsAgent = new AgentKeepAlive__default["default"].HttpsAgent({
    keepAlive: true,
    timeout: 60000,
});
const httpAgent = new AgentKeepAlive__default["default"]({
    keepAlive: true,
    timeout: 60000,
});
let socketId = 0;
class CommonUtils {
    static getOptionsFromRequest(context, proxyConfig, logger) {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        const urlObject = url__default["default"].parse((_b = (_a = context.clientReq) === null || _a === void 0 ? void 0 : _a.url) !== null && _b !== void 0 ? _b : makeErr('No URL set for the request'));
        const defaultPort = context.ssl ? 443 : 80;
        const protocol = context.ssl ? 'https:' : 'http:';
        const headers = { ...context.clientReq.headers };
        let externalProxyHelper;
        try {
            externalProxyHelper = this.getExternalProxyHelper(context, proxyConfig);
            // eslint-disable-next-line no-param-reassign
            context.externalProxy = externalProxyHelper === null || externalProxyHelper === void 0 ? void 0 : externalProxyHelper.getConfigObject();
        }
        catch (error) {
            logger.logError(error, 'Wrong external proxy set');
        }
        delete headers['proxy-connection'];
        delete headers['proxy-authorization'];
        let agent = false;
        if (!externalProxyHelper) {
            // keepAlive
            if (headers.connection !== 'close') {
                if (protocol === 'https:') {
                    agent = httpsAgent;
                }
                else {
                    agent = httpAgent;
                }
                headers.connection = 'keep-alive';
            }
        }
        else {
            agent = TunnelingAgent.getTunnelAgent(protocol === 'https:', externalProxyHelper);
        }
        const requestHost = (_c = headers === null || headers === void 0 ? void 0 : headers.host) !== null && _c !== void 0 ? _c : makeErr('No request hostname set');
        const options = {
            protocol: protocol,
            hostname: requestHost.split(':')[0],
            method: (_d = context.clientReq.method) !== null && _d !== void 0 ? _d : makeErr('No request method set'),
            port: Number(requestHost.split(':')[1] || defaultPort),
            path: (_e = urlObject.path) !== null && _e !== void 0 ? _e : makeErr('No request path set'),
            headers: headers,
            agent: agent,
            timeout: 60000,
            url: `${protocol}//${requestHost}${(_f = urlObject.path) !== null && _f !== void 0 ? _f : ''}`,
        };
        try {
            if (protocol === 'http:' &&
                externalProxyHelper &&
                externalProxyHelper.getProtocol() === 'http:') {
                const externalURL = externalProxyHelper.getUrlObject();
                const host = (_g = externalURL.hostname) !== null && _g !== void 0 ? _g : makeErr(`No external proxy hostname set - ${context.externalProxy}`);
                const port = Number((_h = externalURL.port) !== null && _h !== void 0 ? _h : makeErr(`No external proxy port set - ${context.externalProxy}`));
                options.hostname = host;
                options.port = port;
                // Check if we have authorization here
                const basicAuthString = externalProxyHelper.getBasicAuth();
                if (basicAuthString) {
                    if (!options.headers)
                        options.headers = {};
                    options.headers['Proxy-Authorization'] = `Basic ${basicAuthString}`;
                }
                // support non-transparent proxy
                options.path = `http://${urlObject.host}${urlObject.path}`;
            }
        }
        catch (error) {
            logger.logError(error, 'External proxy parsing problem');
        }
        // TODO: Check if we ever have customSocketId
        // mark a socketId for Agent to bind socket for NTLM
        // @ts-ignore
        if (context.clientReq.socket.customSocketId) {
            // @ts-ignore
            options.customSocketId = context.clientReq.socket.customSocketId;
        }
        else if (headers.authorization) {
            // @ts-ignore
            // eslint-disable-next-line no-param-reassign
            context.clientReq.socket.customSocketId = socketId++;
            // @ts-ignore
            options.customSocketId = context.clientReq.socket.customSocketId;
        }
        return options;
    }
    static getExternalProxyHelper(context, proxyConfig) {
        var _a;
        let externalProxyConfig;
        const externalProxy = proxyConfig.externalProxy;
        const req = context.clientReq;
        if (externalProxy) {
            if (typeof externalProxy === 'string' || isExternalProxyConfigObject(externalProxy)) {
                externalProxyConfig = externalProxy;
            }
            else if (typeof externalProxy === 'function') {
                const connectKey = `${req.socket.remotePort}:${req.socket.localPort}`;
                externalProxyConfig = externalProxy(req, context.ssl, context.clientRes, (_a = contexts[connectKey]) === null || _a === void 0 ? void 0 : _a.connectRequest);
                // Check return type is proper config
                if (externalProxyConfig &&
                    typeof externalProxyConfig !== 'string' &&
                    !isExternalProxyConfigObject(externalProxyConfig)) {
                    throw new TypeError('Invalid externalProxy config generated by external function');
                }
            }
            else {
                throw new TypeError('Invalid externalProxy config provided');
            }
        }
        if (externalProxyConfig)
            return new ExternalProxyHelper(externalProxyConfig);
        return undefined;
    }
}

class StatusData {
    constructor(request, ssl, status, time, externalProxy, requestBytes, responseBytes, serverRequestBytes, serverResponseBytes) {
        /**
         * External proxy config if used
         */
        this.externalProxy = undefined;
        /**
         * Request processing rime
         */
        this.time = 0;
        /**
         * Size of request received from client
         */
        this.requestBytes = 0;
        /**
         * Size of response sent to client
         */
        this.responseBytes = 0;
        /**
         * Size of request sent to end-server
         */
        this.serverRequestBytes = 0;
        /**
         * Size of response from end-server
         */
        this.serverResponseBytes = 0;
        this.request = request;
        this.ssl = ssl;
        this.statusCode = status;
        this.time = time;
        if (externalProxy)
            this.externalProxy = externalProxy;
        if (requestBytes)
            this.requestBytes = requestBytes;
        if (responseBytes)
            this.responseBytes = responseBytes;
        this.serverRequestBytes = serverRequestBytes;
        this.serverResponseBytes = serverResponseBytes;
    }
}

class AbstractContext {
    markStart() {
        this.status_startTime = Date.now();
    }
    markEnd() {
        if (!this.status_endTime)
            this.status_endTime = Date.now();
    }
}

class Context extends AbstractContext {
    constructor(clientReq, clientRes, ssl) {
        super();
        this.status_requestedFromServerBytes = 0;
        this.status_serverRespondedBytes = 0;
        this.clientReq = clientReq;
        this.clientRes = clientRes;
        this.ssl = ssl;
    }
    getStatusData() {
        var _a, _b, _c, _d;
        this.markEnd();
        return new StatusData(this.clientReq, this.ssl, (_a = this.status_code) !== null && _a !== void 0 ? _a : 0, Math.max(0, ((_b = this.status_endTime) !== null && _b !== void 0 ? _b : 0) - ((_c = this.status_startTime) !== null && _c !== void 0 ? _c : 0)), (_d = this.externalProxy) !== null && _d !== void 0 ? _d : undefined, this.clientReq.socket.bytesRead, this.clientReq.socket.bytesWritten, this.status_requestedFromServerBytes, this.status_serverRespondedBytes);
    }
    setStatusCode(statusCode, requestBytes = 0, responseBytes = 0) {
        if (!this.status_code && statusCode)
            this.status_code = statusCode;
        this.status_requestedFromServerBytes = requestBytes;
        this.status_serverRespondedBytes = responseBytes;
    }
}

// create connectHandler function
function createUpgradeHandler(proxyConfig, logger) {
    return function upgradeHandler(req, clientSocket, head, ssl) {
        const context = new Context(req, undefined, false);
        const clientOptions = CommonUtils.getOptionsFromRequest(context, proxyConfig, logger);
        const proxyReq = (ssl ? https__default["default"] : http__default["default"]).request(clientOptions);
        proxyReq.on('error', (error) => {
            logger.logError(error);
        });
        proxyReq.on('response', (res) => {
            // if upgrade event isn't going to happen, close the socket
            // @ts-ignore
            if (!res.upgrade)
                clientSocket.end();
        });
        proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
            proxySocket.on('error', (error) => {
                logger.logError(error);
            });
            clientSocket.on('error', () => {
                proxySocket.end();
            });
            proxySocket.setTimeout(0);
            proxySocket.setNoDelay(true);
            proxySocket.setKeepAlive(true, 0);
            if (proxyHead && proxyHead.length > 0)
                proxySocket.unshift(proxyHead);
            clientSocket.write(`${Object.keys(proxyRes.headers)
                // eslint-disable-next-line unicorn/no-reduce
                .reduce((aggregator, key) => {
                const value = proxyRes.headers[key];
                if (!Array.isArray(value)) {
                    aggregator.push(`${key}: ${value}`);
                    return aggregator;
                }
                for (const element of value) {
                    aggregator.push(`${key}: ${element}`);
                }
                return aggregator;
            }, ['HTTP/1.1 101 Switching Protocols'])
                .join('\r\n')}\r\n\r\n`);
            proxySocket.pipe(clientSocket).pipe(proxySocket);
        });
        proxyReq.end();
    };
}

function doNotWaitPromise(promise, description, logger) {
    promise
        .then(() => { })
        .catch((err) => {
        logger.logError(err, `Error at ${description}`);
    });
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

const localIP = '127.0.0.1';
function connect(context, hostname, port, socketsList) {
    // tunneling https
    const proxySocket = net__default["default"].connect(port, hostname, () => {
        context.clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        proxySocket.write(context.head);
        proxySocket.pipe(context.clientSocket);
        context.clientSocket.pipe(proxySocket);
    });
    socketsList.add(proxySocket);
    proxySocket.on('error', () => {
        // logError(e);
    });
    proxySocket.on('ready', () => {
        proxySocket.connectKey = `${proxySocket.localPort}:${proxySocket.remotePort}`;
        contexts[proxySocket.connectKey] = context;
    });
    proxySocket.on('close', () => {
        socketsList.delete(proxySocket);
    });
    proxySocket.on('end', () => {
        if (proxySocket.connectKey)
            delete contexts[proxySocket.connectKey];
    });
    return proxySocket;
}
function connectNoMitmExternalProxy(proxyHelper, context, hostname, port, logger) {
    const proxySocket = net__default["default"].connect(Number(proxyHelper.getUrlObject().port), proxyHelper.getUrlObject().hostname, () => {
        proxySocket.write(`CONNECT ${hostname}:${port} HTTP/${context.connectRequest.httpVersion}\r\n`);
        ['host', 'user-agent', 'proxy-connection'].forEach((name) => {
            if (name in context.connectRequest.headers) {
                proxySocket.write(`${name}: ${context.connectRequest.headers[name]}\r\n`);
            }
        });
        const proxyAuth = proxyHelper.getLoginAndPassword();
        if (proxyAuth) {
            const basicAuth = Buffer.from(proxyAuth).toString('base64');
            proxySocket.write(`Proxy-Authorization: Basic ${basicAuth}\r\n`);
        }
        proxySocket.write('\r\n');
        proxySocket.pipe(context.clientSocket);
        context.clientSocket.pipe(proxySocket);
    });
    proxySocket.on('error', (e) => {
        logger.logError(e);
    });
    return proxySocket;
}
function createConnectHandler(proxyConfig, fakeServerCenter, logger, socketsList) {
    // return
    return function connectHandler(context) {
        var _a;
        const srvUrl = url__default["default"].parse(`https://${context.connectRequest.url}`);
        let interceptSsl = false;
        try {
            interceptSsl =
                (typeof proxyConfig.sslMitm === 'function' &&
                    proxyConfig.sslMitm.call(null, context.connectRequest, context.clientSocket, context.head)) ||
                    proxyConfig.sslMitm === true;
        }
        catch (error) {
            logger.logError(error, 'Error at sslMitm function');
        }
        if (!context.clientSocket.writable)
            return;
        const serverHostname = (_a = srvUrl.hostname) !== null && _a !== void 0 ? _a : makeErr('No hostname set for https request');
        const serverPort = Number(srvUrl.port || 443);
        if (!interceptSsl) {
            const externalProxy = proxyConfig.externalProxyNoMitm && typeof proxyConfig.externalProxyNoMitm === 'function'
                ? proxyConfig.externalProxyNoMitm(context.connectRequest, context.clientSocket)
                : proxyConfig.externalProxyNoMitm;
            context.markStart();
            context.clientSocket.on('close', () => {
                if (proxyConfig.statusNoMitmFn) {
                    const statusData = context.getStatusData();
                    proxyConfig.statusNoMitmFn(statusData);
                }
            });
            if (externalProxy) {
                connectNoMitmExternalProxy(new ExternalProxyHelper(externalProxy), context, serverHostname, serverPort, logger);
                return;
            }
            connect(context, serverHostname, serverPort, socketsList);
            return;
        }
        doNotWaitPromise((async () => {
            try {
                const server = fakeServerCenter.getFakeServer(serverHostname, serverPort);
                await server.run();
                if (!server.listenPort) {
                    context.clientSocket.end();
                    throw new Error('SSL proxy is not listening');
                }
                connect(context, localIP, server.listenPort, socketsList);
            }
            finally {
            }
        })(), `Connect to fake server failed for ${serverHostname}`, logger);
    };
}

class RequestTimeoutError extends Error {
    constructor(hostPort, timeout) {
        super(`Timeout of ${timeout}ms while requesting ${hostPort}`); // 'Error' breaks prototype chain here
        this.name = 'RequestTimeoutError';
        Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
    }
}

const internalLogger = Debug__default["default"]('newproxy:requestHandler');
class RequestHandler {
    constructor(context, proxyConfig, logger) {
        var _a;
        this.context = context;
        this.proxyConfig = proxyConfig;
        this.logger = logger;
        this.req = context.clientReq;
        this.res = (_a = context.clientRes) !== null && _a !== void 0 ? _a : makeErr('No clientResponse set in context');
        this.rOptions = CommonUtils.getOptionsFromRequest(this.context, this.proxyConfig, logger);
    }
    async go() {
        var _a;
        internalLogger(`Request handler called for request (ssl=${this.context.ssl}) ${this.req.toString()}`);
        if (this.res.writableEnded) {
            return;
        }
        this.setKeepAlive();
        try {
            try {
                await this.interceptRequest();
            }
            catch (error) {
                this.logger.logError(error, 'Problem at request interception');
                if (!this.res.writableEnded) {
                    this.context.setStatusCode(502);
                    this.res.writeHead(502);
                    this.res.write(`Proxy Warning:\r\n\r\n${error}`);
                    this.res.end();
                }
            }
            if (this.res.writableEnded) {
                return;
            }
            try {
                const proxyRequestPromise = this.getProxyRequestPromise();
                this.proxyRes = await proxyRequestPromise;
                this.context.setStatusCode((_a = this.proxyRes) === null || _a === void 0 ? void 0 : _a.statusCode, this.proxyRes.socket.bytesWritten, this.proxyRes.socket.bytesRead);
            }
            catch (error) {
                this.logger.logError(error, 'Problem at request processing');
                if (this.res.writableEnded) {
                    return;
                }
                if (error instanceof RequestTimeoutError) {
                    this.context.setStatusCode(504);
                    this.res.writeHead(504);
                }
                else {
                    this.context.setStatusCode(502);
                    this.res.writeHead(502);
                }
                this.res.write(`Proxy Error:\r\n\r\n${error}`);
                this.res.end();
            }
            if (this.res.writableEnded) {
                return;
            }
            try {
                await this.interceptResponse();
            }
            catch (error) {
                this.logger.logError(error, 'Problem with response interception');
                if (!this.res.writableEnded) {
                    this.res.writeHead(500);
                    this.res.write(`Proxy Warning:\r\n\r\n${error}`);
                    this.res.end();
                }
            }
            if (this.res.writableEnded) {
                return;
            }
            this.sendHeadersAndPipe();
        }
        catch (error) {
            if (!this.res.writableEnded) {
                if (!this.res.headersSent)
                    this.res.writeHead(500);
                this.res.write(`Proxy Warning:\r\n\r\n ${error}`);
                this.res.end();
            }
            this.logger.logError(error);
        }
    }
    sendHeadersAndPipe() {
        if (!this.proxyRes)
            makeErr('No proxy res');
        const proxyRes = this.proxyRes;
        if (this.res.headersSent) {
            internalLogger('Headers sent already');
        }
        else {
            // prevent duplicate set headers
            Object.keys(proxyRes.headers).forEach((key) => {
                try {
                    let headerName = key;
                    const headerValue = proxyRes.headers[headerName];
                    if (headerValue) {
                        // https://github.com/nodejitsu/node-http-proxy/issues/362
                        if (/^www-authenticate$/i.test(headerName)) {
                            if (proxyRes.headers[headerName]) {
                                // @ts-ignore
                                proxyRes.headers[headerName] =
                                    headerValue && typeof headerValue === 'string' && headerValue.split(',');
                            }
                            headerName = 'www-authenticate';
                        }
                        this.res.setHeader(headerName, headerValue);
                    }
                }
                catch (error) {
                    internalLogger(`Error sending header: ${error}`);
                }
            });
            if (proxyRes.statusCode) {
                this.res.writeHead(proxyRes.statusCode);
            }
        }
        if (!this.res.finished)
            try {
                internalLogger('Start piping');
                proxyRes.pipe(this.res);
            }
            catch (error) {
                internalLogger(`Piping error: ${error}`);
            }
    }
    getProxyRequestPromise() {
        const self = this;
        return new Promise((resolve, reject) => {
            this.rOptions.host = this.rOptions.hostname || this.rOptions.host || 'localhost';
            // use the bind socket for NTLM
            const onFree = () => {
                self.proxyReq = (self.rOptions.protocol === 'https:' ? https__default["default"] : http__default["default"]).request(self.rOptions, (proxyRes) => {
                    resolve(proxyRes);
                });
                const timeout = self.rOptions.timeout || 60000;
                self.proxyReq.on('socket', (socket) => {
                    socket.setTimeout(timeout, () => { });
                });
                self.proxyReq.setSocketKeepAlive(true, 5000);
                self.proxyReq.setTimeout(timeout, () => { });
                self.proxyReq.on('timeout', () => {
                    internalLogger(`ProxyRequest timeout for ${self.req.toString()}`);
                    reject(new RequestTimeoutError(`${self.rOptions.host}:${self.rOptions.port}`, timeout));
                });
                self.proxyReq.on('error', (e) => {
                    internalLogger(`ProxyRequest error: ${e.message}`);
                    reject(e);
                });
                self.proxyReq.on('aborted', () => {
                    internalLogger(`ProxyRequest aborted for ${self.req.toString()}`);
                    reject(new Error('Proxy server aborted the request'));
                    // TODO: Check if it's ok
                    // @ts-ignore
                    self.req.abort();
                });
                self.req.on('aborted', () => {
                    var _a;
                    internalLogger(`Request aborted ${self.req.toString}`);
                    // eslint-disable-next-line no-unused-expressions
                    (_a = self.proxyReq) === null || _a === void 0 ? void 0 : _a.abort();
                });
                self.req.pipe(self.proxyReq);
            };
            if (this.rOptions.agent &&
                this.rOptions.agent instanceof http.Agent &&
                isPresent(this.rOptions.customSocketId) &&
                this.rOptions.agent.getName) {
                // @ts-ignore
                logger(`Request started with agent ${this.req.toString}`);
                const socketName = this.rOptions.agent.getName(this.rOptions);
                const bindingSocket = this.rOptions.agent.sockets[socketName];
                if (bindingSocket && bindingSocket.length > 0) {
                    bindingSocket[0].once('free', onFree);
                    return;
                }
            }
            onFree();
        });
    }
    async interceptRequest() {
        var _a;
        if (typeof this.proxyConfig.requestInterceptor === 'function') {
            const connectKey = `${this.req.socket.remotePort}:${this.req.socket.localPort}`;
            await this.proxyConfig.requestInterceptor.call(null, this.rOptions, this.req, this.res, this.context.ssl, (_a = contexts[connectKey]) === null || _a === void 0 ? void 0 : _a.connectRequest);
        }
    }
    async interceptResponse() {
        var _a, _b;
        if (typeof this.proxyConfig.responseInterceptor === 'function') {
            await this.proxyConfig.responseInterceptor.call(null, this.req, this.res, (_a = this.proxyReq) !== null && _a !== void 0 ? _a : makeErr('No proxyReq'), (_b = this.proxyRes) !== null && _b !== void 0 ? _b : makeErr('No proxyRes'), this.context.ssl);
        }
    }
    setKeepAlive() {
        var _a;
        if (((_a = this.rOptions.headers) === null || _a === void 0 ? void 0 : _a.connection) === 'close') {
            this.req.socket.setKeepAlive(false);
        }
        else if (this.rOptions.customSocketId != null) {
            // for NTLM
            this.req.socket.setKeepAlive(true, 60 * 60 * 1000);
        }
        else {
            this.req.socket.setKeepAlive(true, 30000);
        }
    }
}

// create requestHandler function
function createRequestHandler(proxyConfig, logger) {
    return function requestHandler(context) {
        const reqHandler = new RequestHandler(context, proxyConfig, logger);
        context.clientReq.socket.on('close', () => {
            if (proxyConfig === null || proxyConfig === void 0 ? void 0 : proxyConfig.statusFn) {
                const statusData = context.getStatusData();
                proxyConfig.statusFn(statusData);
            }
        });
        // Mark time of request processing start
        context.markStart();
        doNotWaitPromise(reqHandler.go(), 'requestHandler', logger);
    };
}

class CertAndKeyContainer {
    constructor(maxLength = 1000, getCertSocketTimeout = 2 * 1000, caPair, logger) {
        this.logger = logger;
        this.queue = [];
        this.maxLength = maxLength;
        this.getCertSocketTimeout = getCertSocketTimeout;
        this.caPair = caPair;
    }
    addCertPromise(certPromiseObj) {
        if (this.queue.length >= this.maxLength) {
            this.queue.shift();
        }
        this.queue.push(certPromiseObj);
        return certPromiseObj;
    }
    getCertPromise(hostname, port) {
        const havePromise = this.checkIfWeHaveCertPromise(hostname);
        if (havePromise !== undefined)
            return havePromise;
        // @ts-ignore
        const certPromiseObj = {
            mappingHostNames: [hostname], // temporary hostname
        };
        certPromiseObj.promise = this.createNewCertPromise(hostname, port, certPromiseObj);
        return this.addCertPromise(certPromiseObj).promise;
    }
    createNewCertPromise(hostname, port, certPromiseObj) {
        return new Promise((resolve, reject) => {
            let once = true;
            const newResolve = (caPair) => {
                if (once) {
                    once = false;
                    // eslint-disable-next-line no-param-reassign
                    certPromiseObj.mappingHostNames = TlsUtils.getMappingHostNamesFormCert(caPair.cert);
                    resolve(caPair);
                }
            };
            let certObj;
            const preReq = https__default["default"].request({
                port: port,
                hostname: hostname,
                path: '/',
                method: 'HEAD',
            }, (preRes) => {
                try {
                    const realCert = preRes.socket.getPeerCertificate();
                    if (realCert && 'subject' in realCert)
                        try {
                            certObj = TlsUtils.createFakeCertificateByCA(this.caPair, realCert);
                        }
                        catch (error) {
                            this.logger.logError(error);
                        }
                    if (!certObj)
                        certObj = TlsUtils.createFakeCertificateByDomain(this.caPair, hostname);
                    newResolve(certObj);
                }
                catch (error) {
                    reject(error);
                }
            });
            preReq.setTimeout(this.getCertSocketTimeout, () => {
                if (!certObj) {
                    certObj = TlsUtils.createFakeCertificateByDomain(this.caPair, hostname);
                    newResolve(certObj);
                }
            });
            preReq.on('error', () => {
                if (!certObj) {
                    certObj = TlsUtils.createFakeCertificateByDomain(this.caPair, hostname);
                    newResolve(certObj);
                }
            });
            preReq.end();
        });
    }
    checkIfWeHaveCertPromise(hostname) {
        for (let i = 0; i < this.queue.length; i++) {
            const certPromiseObj = this.queue[i];
            const mappingHostNames = certPromiseObj.mappingHostNames;
            // eslint-disable-next-line no-restricted-syntax
            for (const DNSName of mappingHostNames) {
                if (TlsUtils.isMappingHostName(DNSName, hostname)) {
                    this.reRankCert(i);
                    return certPromiseObj.promise;
                }
            }
        }
        return undefined;
    }
    reRankCert(index) {
        // index ==> queue foot
        this.queue.push(this.queue.splice(index, 1)[0]);
    }
}

const pki = forge__default["default"].pki;
class HttpsServer {
    constructor(certAndKeyContainer, logger, remoteHostname, remotePort, requestHandler, upgradeHandler) {
        this.certAndKeyContainer = certAndKeyContainer;
        this.logger = logger;
        this.remoteHostname = remoteHostname;
        this.remotePort = remotePort;
        this.requestHandler = requestHandler;
        this.upgradeHandler = upgradeHandler;
        this._launching = false;
        this._stopped = false;
        this._running = false;
        this.serverSockets = new Set();
        this._mappingHostNames = [];
        this._mappingHostNames = [this.remoteHostname];
    }
    get isLaunching() {
        return this._launching;
    }
    get isRunning() {
        return this._running;
    }
    get listenPort() {
        return this._listenPort;
    }
    get mappingHostNames() {
        return this._mappingHostNames;
    }
    doesMatchHostname(hostname) {
        for (const DNSName of this.mappingHostNames) {
            if (TlsUtils.isMappingHostName(DNSName, hostname)) {
                return true;
            }
        }
        return false;
    }
    async run() {
        if (this._running) {
            return this;
        }
        if (this.isLaunching) {
            // Launching already
            while (this._launching) {
                if (this._launchPromise) {
                    await this._launchPromise;
                }
                await sleep(100);
            }
            return this;
        }
        if (this._stopped) {
            throw new Error('Server is stopped already');
        }
        this._launching = true;
        const certObj = await this.certAndKeyContainer.getCertPromise(this.remoteHostname, this.remotePort);
        const cert = certObj.cert;
        const key = certObj.key;
        const certPem = pki.certificateToPem(cert);
        const keyPem = pki.privateKeyToPem(key);
        this.fakeServer = new https__default["default"].Server({
            key: keyPem,
            cert: certPem,
            SNICallback: (sniHostname, done) => {
                void (async () => {
                    const sniCertObj = await this.certAndKeyContainer.getCertPromise(sniHostname, this.remotePort);
                    done(null, tls__default["default"].createSecureContext({
                        key: pki.privateKeyToPem(sniCertObj.key),
                        cert: pki.certificateToPem(sniCertObj.cert),
                    }));
                })();
            },
        });
        this._launchPromise = new Promise((resolve, reject) => {
            const fakeServer = this.fakeServer;
            fakeServer.once('error', (error) => {
                if (this._launching) {
                    this._launching = false;
                    reject(error);
                }
            });
            fakeServer.listen(0, () => {
                const address = fakeServer.address();
                this._listenPort = address.port;
                this._running = true;
                this._launching = false;
                this.logger.log(`Fake server created at port ${address.port}`);
                this._mappingHostNames = TlsUtils.getMappingHostNamesFormCert(certObj.cert);
                resolve();
            });
            fakeServer.on('request', (req, res) => {
                this.logger.log(`New request received by fake-server: ${res.toString()}`);
                const context = new Context(req, res, true);
                this.requestHandler(context);
            });
            fakeServer.on('error', (e) => {
                this.logger.logError(`Error by fake-server: ${e.toString()}`);
            });
            fakeServer.on('connection', (socket) => {
                this.serverSockets.add(socket);
                socket.on('close', () => {
                    this.serverSockets.delete(socket);
                });
            });
            fakeServer.on('upgrade', (req, socket, head) => {
                const ssl = true;
                this.upgradeHandler(req, socket, head, ssl);
            });
        });
        try {
            await this._launchPromise;
        }
        finally {
            this._launchPromise = undefined;
            this._launching = false;
        }
        return this;
    }
    stop() {
        if (this._stopped || (!this._running && !this._launching)) {
            return Promise.resolve();
        }
        this._stopped = true;
        this._running = false;
        this.serverSockets.forEach((socket) => {
            socket.destroy();
        });
        this.serverSockets = new Set();
        if (this.fakeServer) {
            return new Promise((resolve, reject) => {
                this.fakeServer.close((err) => {
                    if (err)
                        reject(err);
                    resolve();
                });
            });
        }
        return Promise.resolve();
    }
}

class FakeServersCenter {
    constructor(proxyConfig, requestHandler, upgradeHandler, logger) {
        this.requestHandler = requestHandler;
        this.upgradeHandler = upgradeHandler;
        this.logger = logger;
        this.queue = [];
        this.maxFakeServersCount = 100;
        let caPair;
        try {
            fs__default["default"].accessSync(proxyConfig.caCertPath, fs__default["default"].constants.F_OK);
            fs__default["default"].accessSync(proxyConfig.caKeyPath, fs__default["default"].constants.F_OK);
            const caCertPem = String(fs__default["default"].readFileSync(proxyConfig.caCertPath));
            const caKeyPem = String(fs__default["default"].readFileSync(proxyConfig.caKeyPath));
            const caCert = forge__default["default"].pki.certificateFromPem(caCertPem);
            const caKey = forge__default["default"].pki.privateKeyFromPem(caKeyPem);
            caPair = {
                key: caKey,
                cert: caCert,
            };
        }
        catch (error) {
            this.logger.logError(`Can not find \`CA certificate\` or \`CA key\`.`);
            throw error;
        }
        this.certAndKeyContainer = new CertAndKeyContainer(this.maxFakeServersCount, proxyConfig.getCertSocketTimeout, caPair, this.logger);
    }
    getFakeServer(hostname, port) {
        // Look for existing server
        for (let i = 0; i < this.queue.length; i++) {
            const server = this.queue[i];
            if (server.doesMatchHostname(hostname)) {
                this.reRankServer(i);
                return server;
            }
        }
        // Check if we are over limit
        if (this.queue.length >= this.maxFakeServersCount) {
            const serverToDelete = this.queue.shift();
            if (serverToDelete)
                if (serverToDelete.isRunning || serverToDelete.isLaunching) {
                    doNotWaitPromise(serverToDelete.stop(), `Stopping server for ${serverToDelete.mappingHostNames.join(',')}`, this.logger);
                }
        }
        // Create new one
        const newServer = new HttpsServer(this.certAndKeyContainer, this.logger, hostname, port, this.requestHandler, this.upgradeHandler);
        this.queue.push(newServer);
        doNotWaitPromise(newServer.run(), `Server launched for ${hostname}`, this.logger);
        return newServer;
    }
    reRankServer(index) {
        // index ==> queue foot
        this.queue.push(this.queue.splice(index, 1)[0]);
    }
    async close() {
        // Destroy all fake servers
        await Promise.all(this.queue.map((server) => server.stop()));
    }
}

class StatusDataNoMitm {
    constructor(connectRequest, externalProxy, time) {
        this.externalProxy = undefined;
        this.time = 0;
        this.connectRequest = connectRequest;
        this.externalProxy = externalProxy;
        this.time = time;
    }
}

class ContextNoMitm extends AbstractContext {
    constructor(connectRequest, clientSocket, head) {
        super();
        this.connectRequest = connectRequest;
        this.clientSocket = clientSocket;
        this.head = head;
    }
    getStatusData() {
        var _a, _b, _c;
        this.markEnd();
        return new StatusDataNoMitm(this.connectRequest, (_a = this.externalProxy) !== null && _a !== void 0 ? _a : undefined, Math.max(0, ((_b = this.status_endTime) !== null && _b !== void 0 ? _b : 0) - ((_c = this.status_startTime) !== null && _c !== void 0 ? _c : 0)));
    }
}

class NewProxy {
    constructor(proxyConfig, logger) {
        this.proxyConfig = proxyConfig;
        this.logger = logger;
        this.httpServer = new http__default["default"].Server();
        this.serverSockets = new Set();
        this.clientSockets = new Set();
        this.requestHandler = createRequestHandler(this.proxyConfig, logger);
        this.upgradeHandler = createUpgradeHandler(this.proxyConfig, logger);
        this.connectHandler = createConnectHandler(this.proxyConfig, this.fakeServersCenter, this.logger, this.clientSockets);
    }
    get fakeServersCenter() {
        if (!this._fakeServersCenter) {
            this._fakeServersCenter = new FakeServersCenter(this.proxyConfig, this.requestHandler, this.upgradeHandler, this.logger);
        }
        return this._fakeServersCenter;
    }
    run() {
        // Don't reject unauthorized
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        return new Promise((resolve, reject) => {
            this.httpServer.once('error', (error) => {
                reject(error);
            });
            this.httpServer.listen(this.proxyConfig.port, () => {
                this.logger.log(`NewProxy is listening on port ${this.proxyConfig.port}`, chalk__default["default"].green);
                this.httpServer.on('error', (e) => {
                    this.logger.logError(e);
                });
                this.httpServer.on('request', (req, res) => {
                    // Plain HTTP request
                    const context = new Context(req, res, false);
                    this.requestHandler(context);
                });
                // tunneling for https
                this.httpServer.on('connect', (connectRequest, clientSocket, head) => {
                    clientSocket.on('error', () => { });
                    const context = new ContextNoMitm(connectRequest, clientSocket, head);
                    this.connectHandler(context);
                });
                this.httpServer.on('connection', (socket) => {
                    this.serverSockets.add(socket);
                    socket.on('close', () => {
                        this.serverSockets.delete(socket);
                    });
                });
                // TODO: handle WebSocket
                this.httpServer.on('upgrade', (req, socket, head) => {
                    const ssl = false;
                    this.upgradeHandler(req, socket, head, ssl);
                });
                resolve();
            });
        });
    }
    async stop() {
        var _a, _b;
        // Destroy all open sockets first
        this.serverSockets.forEach((socket) => {
            socket.destroy();
        });
        this.clientSockets.forEach((socket) => {
            socket.destroy();
        });
        this.serverSockets = new Set();
        this.clientSockets = new Set();
        const promise = (_b = (_a = this.fakeServersCenter) === null || _a === void 0 ? void 0 : _a.close()) !== null && _b !== void 0 ? _b : Promise.resolve();
        await Promise.all([this.closeServer(), promise]);
    }
    closeServer() {
        return new Promise((resolve, reject) => {
            this.httpServer.close((err) => {
                if (err)
                    reject(err);
                resolve();
            });
        });
    }
}

class NewProxyBuilder {
    constructor() {
        this.config = {
            port: 6789,
            log: true,
            errorLog: true,
            statusFn: undefined,
            statusNoMitmFn: undefined,
            sslMitm: undefined,
            requestInterceptor: undefined,
            responseInterceptor: undefined,
            getCertSocketTimeout: 10000,
            externalProxy: undefined,
            externalProxyNoMitm: undefined,
        };
    }
    static new() {
        return new NewProxyBuilder();
    }
    port(port) {
        this.config.port = port;
        return this;
    }
    sslMitm(value) {
        this.config.sslMitm = value;
        return this;
    }
    requestInterceptor(value) {
        this.config.requestInterceptor = value;
        return this;
    }
    responseInterceptor(value) {
        this.config.responseInterceptor = value;
        return this;
    }
    log(value) {
        this.config.log = value;
        return this;
    }
    metrics(value) {
        this.config.statusFn = value;
        return this;
    }
    errorLog(value) {
        this.config.errorLog = value;
        return this;
    }
    ca(caKeyPath, caCertPath) {
        this.config.caKeyPath = caKeyPath;
        this.config.caCertPath = caCertPath;
        return this;
    }
    externalProxy(value) {
        this.config.externalProxy = value;
        return this;
    }
    externalProxyNoMitm(value) {
        this.config.externalProxyNoMitm = value;
        return this;
    }
    build() {
        const logger = new Logger(this.config.log, this.config.errorLog);
        // Generate certificate if none
        if (!this.config.caCertPath || !this.config.caKeyPath) {
            const rs = TlsUtils.initCA(caConfig.getDefaultCABasePath());
            this.config.caCertPath = rs.caCertPath;
            this.config.caKeyPath = rs.caKeyPath;
            if (rs.create) {
                logger.log(`CA Cert saved in: ${this.config.caCertPath}`, chalk__default["default"].cyan);
                logger.log(`CA private key saved in: ${this.config.caKeyPath}`, chalk__default["default"].cyan);
            }
        }
        return new NewProxy(this.config, logger);
    }
}

exports.NewProxy = NewProxy;
exports.NewProxyBuilder = NewProxyBuilder;
