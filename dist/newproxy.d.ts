import http, { RequestOptions, Agent, IncomingMessage, ServerResponse } from 'http';
import stream from 'stream';
import forge from 'node-forge';

declare type SslMitmFn = (req: http.IncomingMessage, clientSocket: stream.Duplex, head: Buffer) => boolean;

interface ExtendedRequestOptions extends RequestOptions {
    customSocketId?: number;
    agent: Agent & {
        getName: (options: RequestOptions) => string;
    };
    host?: string;
    url: string;
}

declare type RequestInterceptorFn = (requestOptions: ExtendedRequestOptions, clientReq: http.IncomingMessage, clientRes: http.ServerResponse, ssl: boolean, connectRequest: http.IncomingMessage | undefined) => Promise<void>;

declare type ResponseInterceptorFn = (clientReq: http.IncomingMessage, clientRes: http.ServerResponse, proxyReq: http.ClientRequest, proxyRes: http.IncomingMessage, ssl: boolean) => Promise<void>;

declare type LoggingFn = (message: string) => void;

interface ExternalProxyConfigObject {
    host: string;
    port: number;
    username?: string;
    password?: string;
}
declare type ExternalProxyConfig = ExternalProxyConfigObject | string;
declare type ExternalProxyConfigOrNull = ExternalProxyConfig | undefined;

declare class StatusData {
    request: http.IncomingMessage;
    /**
     * If HTTPS was used
     */
    ssl: boolean;
    /**
     * HTTP status code
     */
    statusCode: number;
    /**
     * External proxy config if used
     */
    externalProxy: ExternalProxyConfigObject | undefined;
    /**
     * Request processing rime
     */
    time: number;
    /**
     * Size of request received from client
     */
    requestBytes: number;
    /**
     * Size of response sent to client
     */
    responseBytes: number;
    /**
     * Size of request sent to end-server
     */
    serverRequestBytes: number;
    /**
     * Size of response from end-server
     */
    serverResponseBytes: number;
    constructor(request: http.IncomingMessage, ssl: boolean, status: number, time: number, externalProxy: ExternalProxyConfigObject | undefined, requestBytes: number | undefined, responseBytes: number | undefined, serverRequestBytes: number, serverResponseBytes: number);
}

declare class StatusDataNoMitm {
    connectRequest: http.IncomingMessage;
    externalProxy: ExternalProxyConfigObject | undefined;
    time: number;
    constructor(connectRequest: http.IncomingMessage, externalProxy: ExternalProxyConfigObject | undefined, time: number);
}

declare type StatusFn = (status: StatusData) => void;
declare type StatusNoMitmFn = (status: StatusDataNoMitm) => void;

declare type ErrorLoggingFn = (error: Error, comment?: string | undefined) => void;

declare type ExternalProxyFn = (clientReq: IncomingMessage, ssl: boolean, clientRes: ServerResponse | undefined, connectRequest: IncomingMessage | undefined) => ExternalProxyConfigOrNull;
declare type ExternalProxyNoMitmFn = (connectRequest: IncomingMessage, clientSocket: stream.Duplex) => ExternalProxyConfigOrNull;

interface ProxyConfig {
    port: number;
    log: boolean | LoggingFn;
    errorLog: boolean | ErrorLoggingFn;
    statusFn: StatusFn | undefined;
    statusNoMitmFn: StatusNoMitmFn | undefined;
    sslMitm: SslMitmFn | boolean | undefined;
    requestInterceptor: RequestInterceptorFn | undefined;
    responseInterceptor: ResponseInterceptorFn | undefined;
    getCertSocketTimeout: number;
    externalProxy: ExternalProxyConfig | ExternalProxyFn | undefined;
    externalProxyNoMitm: ExternalProxyConfig | ExternalProxyNoMitmFn | undefined;
    caCertPath: string;
    caKeyPath: string;
}

declare type UpgradeHandlerFn = (req: IncomingMessage, clientSocket: stream.Duplex, head: Buffer, ssl: boolean) => void;

declare abstract class AbstractContext {
    externalProxy: ExternalProxyConfigObject | undefined | null;
    protected status_startTime: number | undefined;
    protected status_endTime: number | undefined;
    markStart(): void;
    markEnd(): void;
}

declare class Context extends AbstractContext {
    clientReq: http.IncomingMessage;
    clientRes: http.ServerResponse | undefined;
    ssl: boolean;
    protected status_code: number | undefined;
    protected status_requestedFromServerBytes: number;
    protected status_serverRespondedBytes: number;
    constructor(clientReq: http.IncomingMessage, clientRes: http.ServerResponse | undefined, ssl: boolean);
    getStatusData(): StatusData;
    setStatusCode(statusCode: number | null | undefined, requestBytes?: number, responseBytes?: number): void;
}

declare type RequestHandlerFn = (context: Context) => void;

declare type ColorFn = (str: string) => string;
declare class Logger {
    private loggerConfig;
    private errorLoggerConfig;
    constructor(loggerConfig?: boolean | LoggingFn, errorLoggerConfig?: boolean | ErrorLoggingFn);
    log(message: string, colorFn?: ColorFn): void;
    logError(message: Error | any, comment?: string): void;
}

interface CaPair {
    key: forge.pki.PrivateKey;
    cert: forge.pki.Certificate;
}

declare class CertAndKeyContainer {
    private logger;
    private queue;
    private readonly maxLength;
    private readonly getCertSocketTimeout;
    private readonly caPair;
    constructor(maxLength: number | undefined, getCertSocketTimeout: number | undefined, caPair: CaPair, logger: Logger);
    private addCertPromise;
    getCertPromise(hostname: string, port: number): Promise<CaPair>;
    private createNewCertPromise;
    private checkIfWeHaveCertPromise;
    protected reRankCert(index: number): void;
}

declare class HttpsServer {
    private readonly certAndKeyContainer;
    private readonly logger;
    readonly remoteHostname: string;
    readonly remotePort: number;
    private readonly requestHandler;
    private readonly upgradeHandler;
    private fakeServer?;
    private _launching;
    private _launchPromise?;
    get isLaunching(): boolean;
    private _stopped;
    private _running;
    get isRunning(): boolean;
    private serverSockets;
    private _listenPort?;
    get listenPort(): number | undefined;
    private _mappingHostNames;
    get mappingHostNames(): string[];
    constructor(certAndKeyContainer: CertAndKeyContainer, logger: Logger, remoteHostname: string, remotePort: number, requestHandler: RequestHandlerFn, upgradeHandler: UpgradeHandlerFn);
    doesMatchHostname(hostname: string): boolean;
    run(): Promise<HttpsServer>;
    stop(): Promise<void>;
}

declare class FakeServersCenter {
    private readonly requestHandler;
    private readonly upgradeHandler;
    private readonly logger;
    private queue;
    private readonly maxFakeServersCount;
    private readonly certAndKeyContainer;
    constructor(proxyConfig: ProxyConfig, requestHandler: RequestHandlerFn, upgradeHandler: UpgradeHandlerFn, logger: Logger);
    getFakeServer(hostname: string, port: number): HttpsServer;
    private reRankServer;
    close(): Promise<void>;
}

declare class NewProxy {
    private readonly proxyConfig;
    private readonly logger;
    readonly httpServer: http.Server;
    private readonly requestHandler;
    private readonly upgradeHandler;
    private readonly connectHandler;
    private serverSockets;
    private clientSockets;
    private _fakeServersCenter?;
    constructor(proxyConfig: ProxyConfig, logger: Logger);
    get fakeServersCenter(): FakeServersCenter;
    run(): Promise<void>;
    stop(): Promise<void>;
    private closeServer;
}

declare class NewProxyBuilder {
    private config;
    static new(): NewProxyBuilder;
    port(port: number): NewProxyBuilder;
    sslMitm(value: SslMitmFn | boolean): NewProxyBuilder;
    requestInterceptor(value: RequestInterceptorFn): NewProxyBuilder;
    responseInterceptor(value: ResponseInterceptorFn): NewProxyBuilder;
    log(value: boolean | LoggingFn): NewProxyBuilder;
    metrics(value: StatusFn): NewProxyBuilder;
    errorLog(value: boolean | ErrorLoggingFn): NewProxyBuilder;
    ca(caKeyPath: string, caCertPath: string): NewProxyBuilder;
    externalProxy(value: ExternalProxyConfig | ExternalProxyFn | undefined): NewProxyBuilder;
    externalProxyNoMitm(value: ExternalProxyConfig | ExternalProxyNoMitmFn | undefined): NewProxyBuilder;
    build(): NewProxy;
}

export { NewProxy, NewProxyBuilder };
