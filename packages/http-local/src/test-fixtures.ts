import http from "node:http";
import type { AddressInfo } from "node:net";

export interface RecordedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
}

export interface FixtureServer {
  port: number;
  requests: RecordedRequest[];
  close: () => Promise<void>;
}

/** Starts a throwaway HTTP server on 127.0.0.1 with a random port. Test-only helper. */
export async function startFixtureServer(handler: http.RequestListener): Promise<FixtureServer> {
  const requests: RecordedRequest[] = [];
  const server = http.createServer((request, response) => {
    requests.push({
      method: request.method ?? "",
      url: request.url ?? "",
      headers: request.headers,
    });
    handler(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
