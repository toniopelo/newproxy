import * as http from 'http';
import * as stream from 'stream';
import * as chalk from 'chalk';
import { ProxyConfig, UserProxyConfig } from './types/proxy-config';
import TlsUtils from './tls/tls-utils';
import { createUpgradeHandler } from './mitmproxy/create-upgrade-handler';
import { createFakeServerCenter } from './mitmproxy/create-fake-server-center';
import { createConnectHandler } from './mitmproxy/create-connect-handler';
import { createRequestHandler } from './mitmproxy/create-request-handler';
import { caConfig } from './common/ca-config';
import { log, logError, setErrorLoggerConfig, setLoggerConfig } from './common/logger';
import { makeErr } from './common/common-utils';
import { SslConnectInterceptorFn } from './types/functions/ssl-connect-interceptor';
import { RequestInterceptorFn } from './types/functions/request-interceptor-fn';
import { ResponseInterceptorFn } from './types/functions/response-interceptor-fn';
import { ExternalProxyFn } from './types/functions/external-proxy-fn';
import { LoggingFn } from './types/functions/log-fn';
import { RequestHandlerFn } from './types/functions/request-handler-fn';
import { UpgradeHandlerFn } from './types/functions/upgrade-handler-fn';
import { ConnectHandlerFn } from './types/functions/connect-handler-fn';
import { FakeServersCenter } from './tls/fake-servers-center';
import { ErrorLoggingFn } from './types/functions/error-logging-fn';

// eslint-disable-next-line import/no-default-export
export default class NewProxy {
  protected proxyConfig: ProxyConfig;

  private server: http.Server;

  private requestHandler?: RequestHandlerFn;

  private upgradeHandler?: UpgradeHandlerFn;

  private fakeServersCenter?: FakeServersCenter;

  private connectHandler?: ConnectHandlerFn;

  public constructor(userProxyConfig: UserProxyConfig = {}) {
    this.proxyConfig = NewProxy.setDefaultsForConfig(userProxyConfig);
    this.server = new http.Server();
  }

  public port(port: number): NewProxy {
    this.proxyConfig.port = port;
    return this;
  }

  public sslConnectInterceptor(value: SslConnectInterceptorFn | boolean): NewProxy {
    this.proxyConfig.sslConnectInterceptor = value;
    return this;
  }

  public requestInterceptor(value: RequestInterceptorFn): NewProxy {
    this.proxyConfig.requestInterceptor = value;
    return this;
  }

  public responseInterceptor(value: ResponseInterceptorFn): NewProxy {
    this.proxyConfig.responseInterceptor = value;
    return this;
  }

  public log(value: boolean | LoggingFn): NewProxy {
    this.proxyConfig.log = value;
    return this;
  }

  public errorLog(value: boolean | ErrorLoggingFn): NewProxy {
    this.proxyConfig.errorLog = value;
    return this;
  }

  public ca(caKeyPath: string, caCertPath: string): NewProxy {
    this.proxyConfig.caKeyPath = caKeyPath;
    this.proxyConfig.caCertPath = caCertPath;
    return this;
  }

  public externalProxy(value: string | ExternalProxyFn): NewProxy {
    this.proxyConfig.externalProxy = value;
    return this;
  }

  private static setDefaultsForConfig(userConfig: UserProxyConfig): ProxyConfig {
    let { caCertPath, caKeyPath } = userConfig;

    if (!userConfig.caCertPath || !userConfig.caKeyPath) {
      const rs = TlsUtils.initCA(caConfig.getDefaultCABasePath());
      caCertPath = rs.caCertPath;
      caKeyPath = rs.caKeyPath;

      if (rs.create) {
        log(`CA Cert saved in: ${caCertPath}`, chalk.cyan);
        log(`CA private key saved in: ${caKeyPath}`, chalk.cyan);
      }
    }

    return {
      port: userConfig.port || 6789,

      log: userConfig.log || true,
      errorLog: userConfig.errorLog || true,

      sslConnectInterceptor: userConfig.sslConnectInterceptor || undefined,
      requestInterceptor: userConfig.requestInterceptor || undefined,
      responseInterceptor: userConfig.responseInterceptor || undefined,

      getCertSocketTimeout: userConfig.getCertSocketTimeout || 10000,

      externalProxy: userConfig.externalProxy || null,

      caCertPath: caCertPath ?? makeErr('No caCertPath'),
      caKeyPath: caKeyPath ?? makeErr('No caKeyPath'),
    };
  }

  public setup(): void {
    this.proxyConfig = NewProxy.setDefaultsForConfig(this.proxyConfig);

    setLoggerConfig(this.proxyConfig.log);
    setErrorLoggerConfig(this.proxyConfig.errorLog);

    this.requestHandler = createRequestHandler(this.proxyConfig);
    this.upgradeHandler = createUpgradeHandler(this.proxyConfig);
    this.fakeServersCenter = createFakeServerCenter(
      this.proxyConfig,
      this.requestHandler,
      this.upgradeHandler,
    );

    this.connectHandler = createConnectHandler(
      this.proxyConfig.sslConnectInterceptor,
      this.fakeServersCenter,
    );
  }

  public run(): void {
    // Don't reject unauthorized
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    this.setup();

    this.server.listen(this.proxyConfig.port, () => {
      log(`NewProxy is listening on port ${this.proxyConfig.port}`, chalk.green);

      this.server.on('error', (e: Error) => {
        logError(e);
      });

      this.server.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
        const ssl = false;
        this.requestHandler!!(req, res, ssl);
      });

      // tunneling for https
      this.server.on(
        'connect',
        (req: http.IncomingMessage, clientSocket: stream.Duplex, head: Buffer) => {
          clientSocket.on('error', () => {});
          this.connectHandler!!(req, clientSocket, head);
        },
      );

      // TODO: handle WebSocket
      this.server.on(
        'upgrade',
        (req: http.IncomingMessage, socket: stream.Duplex, head: Buffer) => {
          const ssl = false;
          this.upgradeHandler!!(req, socket, head, ssl);
        },
      );
    });
  }

  public stop(): void {
    this.server.close(() => {});
  }
}
