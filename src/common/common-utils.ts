import * as url from 'url';
// @ts-ignore
import * as tunnelAgent from 'tunnel-agent';
import * as http from 'http';
import * as AgentKeepAlive from 'agentkeepalive';
import { ExternalProxyFn } from '../types/functions/external-proxy-fn';
import { ExtendedRequestOptions } from '../types/request-options';
import { logError } from './logger';
import { ExternalProxyConfig, ExternalProxyHelper } from '../types/external-proxy-config';
import connections from './connections';

const httpsAgent = new AgentKeepAlive.HttpsAgent({
  keepAlive: true,
  timeout: 60000,
});

const httpAgent = new AgentKeepAlive({
  keepAlive: true,
  timeout: 60000,
});

let socketId = 0;

export function makeErr(message: string): never {
  throw new Error(message);
}

export class CommonUtils {
  public static getOptionsFromRequest(
    req: http.IncomingMessage,
    ssl: boolean,
    externalProxy: ExternalProxyConfig | ExternalProxyFn | undefined,
    res?: http.ServerResponse | undefined,
  ): ExtendedRequestOptions {
    const urlObject = url.parse(req?.url ?? makeErr('No URL set for the request'));
    const defaultPort = ssl ? 443 : 80;
    const protocol = ssl ? 'https:' : 'http:';
    const headers = Object.assign({}, req.headers);

    let externalProxyHelper = null;
    try {
      externalProxyHelper = this.getExternalProxyHelper(externalProxy, req, ssl, res);
    } catch (error) {
      logError(error, 'Wrong external proxy set');
    }

    delete headers['proxy-connection'];

    let agent: any = false;
    if (!externalProxyHelper) {
      // keepAlive
      if (headers.connection !== 'close') {
        if (protocol === 'https:') {
          agent = httpsAgent;
        } else {
          agent = httpAgent;
        }
        headers.connection = 'keep-alive';
      }
    } else {
      agent = CommonUtils.getTunnelAgent(protocol === 'https:', externalProxyHelper);
    }

    const requestHost: string = req.headers?.host ?? makeErr('No request hostname set');

    const options: ExtendedRequestOptions = {
      protocol: protocol,
      hostname: requestHost.split(':')[0],
      method: req.method ?? makeErr('No request method set'),
      port: Number(requestHost.split(':')[1] || defaultPort),
      path: urlObject.path ?? makeErr('No request path set'),
      headers: req.headers,
      agent: agent,
      url: `${protocol}//${requestHost}${urlObject.path ?? ''}`,
    };

    try {
      if (
        protocol === 'http:' &&
        externalProxyHelper &&
        externalProxyHelper.getProtocol() === 'http:'
      ) {
        const externalURL = externalProxyHelper.getUrlObject();
        const host =
          externalURL.hostname ?? makeErr(`No external proxy hostname set - ${externalProxy}`);

        const port = Number(
          externalURL.port ?? makeErr(`No external proxy port set - ${externalProxy}`),
        );

        options.hostname = host;
        options.port = port;

        // support non-transparent proxy
        options.path = `http://${urlObject.host}${urlObject.path}`;
      }
    } catch (error) {
      logError(error, 'External proxy parsing problem');
    }

    // TODO: Check if we ever have customSocketId
    // mark a socketId for Agent to bind socket for NTLM
    // @ts-ignore
    if (req.socket.customSocketId) {
      // @ts-ignore
      options.customSocketId = req.socket.customSocketId;
    } else if (headers.authorization) {
      // @ts-ignore
      req.socket.customSocketId = socketId++;
      // @ts-ignore
      options.customSocketId = req.socket.customSocketId;
    }

    return options;
  }

  private static getExternalProxyHelper(
    externalProxy: ExternalProxyConfig | ExternalProxyFn | undefined,
    req: http.IncomingMessage,
    ssl: boolean,
    res: http.ServerResponse | undefined,
  ): ExternalProxyHelper | undefined {
    let externalProxyConfig: ExternalProxyConfig | undefined;

    if (externalProxy) {
      if (typeof externalProxy === 'string') {
        externalProxyConfig = externalProxy;
      } else if (typeof externalProxy === 'function') {
        const connectKey = `${req.socket.remotePort}:${req.socket.localPort}`;
        externalProxyConfig = externalProxy(req, ssl, res, connections[connectKey]);
      }
    }

    if (externalProxyConfig) return new ExternalProxyHelper(externalProxyConfig);

    return undefined;
  }

  private static getTunnelAgent(isSsl: boolean, externalProxyHelper: ExternalProxyHelper): any {
    const urlObject = externalProxyHelper.getUrlObject();
    const externalProxyProtocol = urlObject.protocol || 'http:';
    const port: number | null = Number(
      urlObject?.port ?? (externalProxyProtocol === 'http:' ? 80 : 443),
    );

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

    if (isSsl) {
      if (externalProxyProtocol === 'http:') {
        return tunnelAgent.httpsOverHttp(tunnelConfig);
      }
      return tunnelAgent.httpsOverHttps(tunnelConfig);
    }

    if (externalProxyProtocol === 'http:') {
      // if (!httpOverHttpAgent) {
      //     httpOverHttpAgent = tunnelAgent.httpOverHttp(tunnelConfig);
      // }
      return false;
    }

    return tunnelAgent.httpOverHttps(tunnelConfig);
  }
}
