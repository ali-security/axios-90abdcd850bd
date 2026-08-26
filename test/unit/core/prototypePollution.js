"use strict";

import assert from "assert";
import http from "http";
import stream from "stream";
import { EventEmitter } from "events";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import buildURL from "../../../lib/helpers/buildURL.js";
import resolveConfig from "../../../lib/helpers/resolveConfig.js";
import httpAdapter from "../../../lib/adapters/http.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import AxiosError from "../../../lib/core/AxiosError.js";

const nodeMajorVersion = parseInt(process.versions.node.split(".")[0], 10);

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.adapter;
    delete Object.prototype.headers;
    delete Object.prototype.transitional;
    delete Object.prototype.responseType;
    delete Object.prototype.responseEncoding;
    delete Object.prototype.httpVersion;
    delete Object.prototype.response;
    delete Object.prototype.validateStatus;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.proxy;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.fetchOptions;
    delete Object.prototype.username;
    delete Object.prototype.password;
    delete Object.prototype.hostname;
    delete Object.prototype.host;
    delete Object.prototype.port;
    delete Object.prototype.protocol;
    delete Object.prototype.get;
    delete Object.prototype.set;
    delete Object.prototype.customNested;
    delete Object.prototype.data;
    delete Object.prototype.encode;
    delete Object.prototype.serialize;
    delete Object.prototype.Authorization;
    delete Object.prototype[Symbol.iterator];
    delete Object.prototype[Symbol.toStringTag];
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    // The four tests below are the actual exploits: the key IS present on one
    // of the two configs, so it is visited, and the *other* config resolves the
    // value through the polluted Object.prototype.
    it("should not read a missing config2 key from Object.prototype (defaultToConfig2)", function () {
      Object.prototype.adapter = "evil-adapter";

      const result = mergeConfig({ adapter: ["http"] }, { url: "/a" });

      assert.deepStrictEqual(result.adapter, ["http"]);
      assert.notStrictEqual(result.adapter, "evil-adapter");
    });

    it("should not read a missing config2 key from Object.prototype (mergeDeepProperties)", function () {
      Object.prototype.env = { FormData: "evil" };

      const result = mergeConfig({ env: { FormData: "real" } }, { url: "/a" });

      assert.strictEqual(result.env.FormData, "real");
    });

    it("should not read a missing config1 key from Object.prototype (headers)", function () {
      Object.prototype.headers = { "X-Injected": "evil" };

      const result = mergeConfig(
        {},
        { headers: { "Content-Type": "application/json" } },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.headers, "X-Injected"),
        false,
      );
    });

    it("should not fall back to Object.prototype when config2 has the key set to undefined", function () {
      Object.prototype.transport = {
        request: function () {
          throw new Error("polluted transport was used");
        },
      };

      const result = mergeConfig({}, { transport: undefined, url: "/a" });

      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false,
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  // GHSA-w9j2-pvgh-6h63: mergeDirectKeys must not inherit validateStatus from
  // Object.prototype (was using the `in` operator which traverses the chain).
  describe("GHSA-w9j2-pvgh-6h63 validateStatus merge", function () {
    it("should not inherit a polluted validateStatus during mergeConfig", function () {
      Object.prototype.validateStatus = function () {
        return true;
      };

      const merged = mergeConfig(defaults, { url: "/x" });

      assert.strictEqual(merged.validateStatus, defaults.validateStatus);
    });

    it("should keep 4xx/5xx responses rejected when Object.prototype.validateStatus is polluted", async function () {
      this.timeout(10000);

      Object.prototype.validateStatus = function () {
        return true;
      };

      const server = http.createServer(function (req, res) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end('{"error":"unauthorized"}');
      });

      await new Promise(function (resolve) {
        server.listen(0, "127.0.0.1", resolve);
      });
      const port = server.address().port;

      try {
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${port}/`);
        } catch (err) {
          threw = true;
          assert.strictEqual(err.response.status, 401);
        }
        assert.strictEqual(threw, true);
      } finally {
        await new Promise(function (resolve) {
          server.close(resolve);
        });
      }
    });
  });

  describe("defaults transforms", function () {
    it("should not read formSerializer from Object.prototype", function () {
      Object.prototype.formSerializer = {
        visitor: function () {
          this.append("hijacked", "1");
          return false;
        },
      };

      const headers = new AxiosHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
      });
      const result = defaults.transformRequest[0].call({}, { a: 1 }, headers);

      assert.strictEqual(result, "a=1");
    });

    it("should not read env from Object.prototype", function () {
      let constructed = false;

      function EvilFormData() {
        constructed = true;
        this.append = function () {};
      }

      Object.prototype.env = { FormData: EvilFormData };

      const headers = new AxiosHeaders({
        "Content-Type": "multipart/form-data",
      });

      try {
        defaults.transformRequest[0].call({}, { a: 1 }, headers);
      } catch (e) {
        // the platform FormData may be unavailable on old runtimes - what
        // matters is that the inherited one was never picked up
      }

      assert.strictEqual(constructed, false);
    });

    it("should not read parseReviver from Object.prototype", function () {
      Object.prototype.parseReviver = function (key, value) {
        return typeof value === "number" ? "hijacked" : value;
      };

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(result.a, 1);
    });

    it("should not read transitional from Object.prototype", function () {
      Object.prototype.transitional = {
        forcedJSONParsing: false,
        silentJSONParsing: true,
      };

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not read responseType from Object.prototype", function () {
      Object.prototype.responseType = "text";

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not read response from Object.prototype", function () {
      Object.prototype.response = { status: 999, data: "attacker" };

      let thrown = null;

      try {
        defaults.transformResponse[0].call(
          {
            responseType: "json",
            transitional: {
              forcedJSONParsing: true,
              silentJSONParsing: false,
            },
          },
          "{not json",
        );
      } catch (e) {
        thrown = e;
      }

      assert.ok(thrown, "expected a strict JSON parsing error");
      // `thrown` inherits from Object.prototype, so only an own property proves
      // the polluted value was actually attached to the error
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(thrown, "response"),
        false,
      );
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(thrown, "status"),
        false,
      );
    });
  });

  describe("http adapter", function () {
    let server = null;
    let baseURL = null;

    beforeEach(async function () {
      this.timeout(10000);

      server = http.createServer(function (req, res) {
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Connection", "close");
        res.end('{"ok":true}');
      });

      await new Promise(function (resolve) {
        server.listen(0, "127.0.0.1", resolve);
      });

      baseURL = "http://127.0.0.1:" + server.address().port + "/";
    });

    afterEach(async function () {
      this.timeout(10000);

      if (server) {
        const closing = server;
        server = null;

        if (typeof closing.closeAllConnections === "function") {
          closing.closeAllConnections();
        }

        await new Promise(function (resolve) {
          closing.close(resolve);
        });
      }
    });

    it("should not use a transport inherited from Object.prototype", async function () {
      this.timeout(10000);

      let used = false;

      Object.prototype.transport = {
        request: function () {
          used = true;
          throw new Error("polluted transport was used");
        },
      };

      const response = await axios.get(baseURL);

      assert.strictEqual(used, false);
      assert.strictEqual(response.data.ok, true);
    });

    it("should not use a responseType inherited from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.responseType = "stream";

      const response = await axios.get(baseURL);

      assert.strictEqual(typeof response.data, "object");
      assert.strictEqual(response.data.ok, true);
      assert.strictEqual(typeof response.data.pipe, "undefined");
    });

    it("should not use a responseEncoding inherited from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.responseEncoding = "base64";

      const response = await axios.get(baseURL, { responseType: "text" });

      assert.strictEqual(response.data, '{"ok":true}');
    });

    it("should not use an httpVersion inherited from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.httpVersion = "not-a-number";

      const response = await axios.get(baseURL);

      assert.strictEqual(response.data.ok, true);
    });

    it("should not use env inherited from Object.prototype for data: URLs", async function () {
      this.timeout(10000);

      let constructed = false;

      function EvilBlob() {
        constructed = true;
      }

      Object.prototype.env = { Blob: EvilBlob };

      // the adapter is invoked directly with a config that has no own `env`,
      // so the polluted prototype is the only thing that could supply one
      let response = null;
      let error = null;

      try {
        response = await httpAdapter({
          method: "GET",
          url: "data:text/plain;base64,SGVsbG8=",
          responseType: "blob",
        });
      } catch (e) {
        error = e;
      }

      assert.strictEqual(
        constructed,
        false,
        "the Blob inherited from Object.prototype was used",
      );

      // prove fromDataURI was actually reached: it either produced a value via
      // the platform Blob, or reported that this runtime has no Blob at all
      assert.ok(
        response || (error && /Blob is not supported/.test(error.message)),
        "expected the data: URL to be decoded, got: " +
          (error && error.message),
      );
    });
  });

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and resolveConfig, bypassing hasOwnProperty and
  // allowing prototype pollution gadgets (auth, baseURL, socketPath,
  // beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.auth', async function () {
      this.timeout(10000);
      // setProxy reads `proxy.auth` directly. When `proxy` is a
      // URL instance from the environment proxy or a plain object without an own `auth`,
      // a polluted Object.prototype.auth would otherwise be base64-encoded into the
      // Proxy-Authorization header, leaking attacker-controlled credentials.
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.auth must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.username', async function () {
      this.timeout(10000);
      // The setProxy username/password branch builds basic creds from `proxy.username`
      // and `proxy.password`. For a plain object proxy, both reads must be guarded
      // against prototype pollution.
      Object.prototype.username = 'attacker';
      Object.prototype.password = 'exfil';

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.username must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj resolveConfig baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe('utils.merge prototype-chain read', function () {
    it('should not pick up polluted Object.prototype.<key> as the existing value', function () {
      Object.prototype.headers = { evil: 'yes' };

      const result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      assert.strictEqual(result.headers.evil, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
    });

    it('should not absorb polluted nested objects when the key is absent from inputs', function () {
      // When the source does not carry `customNested`, the merged result should
      // not surface it either, even if Object.prototype carries it.
      Object.prototype.customNested = { evil: 'yes' };

      const result = utils.merge({}, { safe: 'value' });

      assert.strictEqual(Object.prototype.hasOwnProperty.call(result, 'customNested'), false);
      assert.strictEqual(result.safe, 'value');
    });
  });

  // Object.defineProperty calls a HasProperty check on `get`/`set` of the
  // descriptor. A polluted Object.prototype.get with a non-function value would
  // throw TypeError at every defineProperty site that uses a plain literal
  // descriptor. Each fixed site should be shielded with `__proto__: null`.
  describe('Object.defineProperty descriptor literals', function () {
    it('should construct AxiosError when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const err = new AxiosError('hello', 'ECODE');

      assert.strictEqual(err.message, 'hello');
      assert.strictEqual(err.code, 'ECODE');
    });

    it('should build AxiosError.from with a cause when Object.prototype.get is polluted', function () {
      // AxiosError.from defines the non-enumerable `cause` slot with a literal
      // descriptor, so it is one of the live defineProperty sites in this version.
      Object.prototype.get = 'attacker';

      const original = new Error('boom');
      const err = AxiosError.from(original, 'ECODE');

      assert.strictEqual(err.cause, original);
      assert.strictEqual(err.message, 'boom');
    });

    it('should construct AxiosHeaders accessor methods when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // AxiosHeaders.accessor uses Object.defineProperty on the prototype.
      // Triggering a fresh accessor definition exercises the descriptor literal.
      AxiosHeaders.accessor('X-Pp-Test');

      const h = new AxiosHeaders();
      h.setXPpTest('value');
      assert.strictEqual(h.getXPpTest(), 'value');
    });

    it('should not throw in mergeConfig when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const result = mergeConfig({}, { url: '/x', method: 'get' });

      assert.strictEqual(result.url, '/x');
      assert.strictEqual(result.method, 'get');
      assert.strictEqual(typeof result.hasOwnProperty, 'function');
    });

    it('should not throw in utils.extend when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const a = {};
      const b = { x: 1, fn() {} };
      utils.extend(a, b);

      assert.strictEqual(a.x, 1);
      assert.strictEqual(typeof a.fn, 'function');
    });

    it('should not throw in utils.extend with thisArg when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const a = {};
      const ctx = { tag: 'ctx' };
      const b = {
        method() {
          return this.tag;
        },
      };
      utils.extend(a, b, ctx);

      assert.strictEqual(a.method(), 'ctx');
    });

    it('should not throw in utils.inherits when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      function Parent() {}
      function Child() {}
      utils.inherits(Child, Parent);

      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it('should also be shielded against a polluted Object.prototype.set', function () {
      Object.prototype.set = 'attacker';

      // Same surface as `get` — ToPropertyDescriptor checks both. One spot-check
      // covers them all since they share the same fix.
      const err = AxiosError.from(new Error('hello'));
      assert.strictEqual(err.message, 'hello');
    });
  });

  // End-to-end regressions covering published advisory PoCs against full axios
  // request flow. Each test mirrors the exploit scenario from the advisory and
  // asserts the attack does not succeed.
  describe('advisory regression — full request flow', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    // Full MITM via prototype pollution gadget in
    // `config.proxy`. mergeConfig must not surface a polluted Object.prototype.proxy
    // as the merged config's proxy, otherwise every request would route through
    // an attacker-controlled host.
    it('polluted Object.prototype.proxy must not redirect requests through an attacker proxy', async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startServer((req, res) => {
        proxyHits.push({
          url: req.url,
          authorization: req.headers.authorization,
          host: req.headers.host,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });

      const realHits = [];
      const realServer = await startServer((req, res) => {
        realHits.push({ url: req.url });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":"real"}');
      });

      try {
        Object.prototype.proxy = {
          protocol: 'http',
          host: '127.0.0.1',
          port: attackerProxy.address().port,
        };

        const realPort = realServer.address().port;
        const res = await axios.get(`http://127.0.0.1:${realPort}/api/secrets`, {
          auth: { username: 'admin', password: 'SuperSecret123!' },
        });

        assert.strictEqual(proxyHits.length, 0, 'attacker proxy must not receive any request');
        assert.strictEqual(realHits.length, 1, 'request must reach the real target');
        assert.deepStrictEqual(res.data, { data: 'real' });
      } finally {
        await stop(attackerProxy);
        await stop(realServer);
      }
    });

    // Credential theft and response hijacking via
    // prototype pollution gadget in config merge. A polluted
    // Object.prototype.transformResponse function would otherwise execute with
    // `this = config`, exposing `auth.username`/`auth.password` to the attacker.
    it('polluted Object.prototype.transformResponse must not be invoked or leak request credentials', async function () {
      this.timeout(10000);
      let invoked = false;
      let stolen = null;
      Object.prototype.transformResponse = function pollutedTransform(data) {
        invoked = true;
        stolen = {
          url: this && this.url,
          username: this && this.auth && this.auth.username,
          password: this && this.auth && this.auth.password,
          data,
        };
        return true;
      };

      const server = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"secret":"keep-me"}');
      });

      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/users`, {
          auth: { username: 'svc-account', password: 'prod-secret-key-123!' },
        });

        assert.strictEqual(invoked, false, 'polluted transformResponse must not run');
        assert.strictEqual(stolen, null, 'no request context must be captured');
        assert.deepStrictEqual(
          res.data,
          { secret: 'keep-me' },
          'response data must reach the caller untampered'
        );
      } finally {
        await stop(server);
      }
    });
  });

  // GHSA-jqh4-m9w3-8hp9: nested option objects (`auth`, `paramsSerializer`) and
  // the Symbol.iterator used to detect key-value header sources were still read
  // straight off the object, so `Object.prototype.username` / `.serialize` /
  // `Object.prototype[Symbol.iterator]` remained reachable gadgets. Reads now go
  // through utils.getSafeProp / utils.isSafeIterable, which honour own members
  // and members inherited from a non-Object.prototype source but ignore anything
  // whose only home is Object.prototype.
  describe('GHSA-jqh4-m9w3-8hp9 nested option and Symbol gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    describe('utils.hasOwnInPrototypeChain / getSafeProp', function () {
      it('should ignore a value whose only home is Object.prototype', function () {
        Object.prototype.customNested = 'polluted';

        assert.strictEqual(utils.hasOwnInPrototypeChain({}, 'customNested'), false);
        assert.strictEqual(utils.getSafeProp({}, 'customNested'), undefined);
      });

      it('should honour an own property and one inherited from a custom prototype', function () {
        Object.prototype.customNested = 'polluted';

        assert.strictEqual(utils.getSafeProp({ customNested: 'own' }, 'customNested'), 'own');

        const template = Object.create(null);
        template.customNested = 'template';
        assert.strictEqual(utils.getSafeProp(Object.create(template), 'customNested'), 'template');
      });

      it('should return undefined for null and undefined sources', function () {
        assert.strictEqual(utils.getSafeProp(null, 'customNested'), undefined);
        assert.strictEqual(utils.getSafeProp(undefined, 'customNested'), undefined);
      });

      it('should stop safe prototype-chain reads on cyclic Proxy prototypes', function () {
        let calls = 0;
        let proxy;
        proxy = new Proxy({}, {
          getPrototypeOf: function () {
            calls += 1;
            if (calls > 5) {
              throw new Error('cycled');
            }
            return proxy;
          }
        });

        assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, 'missing'), false);
        assert.strictEqual(utils.getSafeProp(proxy, 'missing'), undefined);
        assert.ok(calls <= 2, 'prototype chain walk must terminate, saw ' + calls + ' reads');
      });
    });

    describe('utils.isPlainObject / isSafeIterable symbol pollution', function () {
      it('should ignore inherited symbol properties when validating plain Object', function () {
        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['x-injected', 'yes'];
          };
          Object.prototype[Symbol.toStringTag] = 'Custom';

          assert.strictEqual(utils.isPlainObject({}), true);
          assert.strictEqual(utils.isPlainObject([]), false);
          assert.strictEqual(utils.isPlainObject({
            [Symbol.iterator]: function* () {
              yield ['x-own', 'yes'];
            }
          }), false);
          assert.strictEqual(utils.isPlainObject({
            [Symbol.toStringTag]: 'Custom'
          }), false);
        } finally {
          delete Object.prototype[Symbol.iterator];
          delete Object.prototype[Symbol.toStringTag];
        }
      });

      it('should treat an object with a genuinely inherited iterator as non-plain', function () {
        // Iterator inherited from a custom (non-Object.prototype) source: this is
        // a real iterable, not prototype pollution, so it must not be plain.
        const proto = Object.create(null);
        proto[Symbol.iterator] = function* () {
          yield ['x', '1'];
        };

        assert.strictEqual(utils.isPlainObject(Object.create(proto)), false);
      });

      it('should not read polluted Object.prototype iterator accessors for safe iterable checks', function () {
        let accessed = false;

        try {
          Object.defineProperty(Object.prototype, Symbol.iterator, {
            configurable: true,
            get: function () {
              accessed = true;
              throw new Error('polluted iterator accessor');
            }
          });

          assert.strictEqual(utils.isSafeIterable({}), false);
          assert.strictEqual(accessed, false);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should still report a genuine iterable as safely iterable', function () {
        assert.strictEqual(utils.isSafeIterable(new Map([['x', '1']])), true);
        assert.strictEqual(utils.isSafeIterable([['x', '1']]), true);
        assert.strictEqual(utils.isSafeIterable(null), false);
      });
    });

    describe('AxiosHeaders iterable source', function () {
      it('should not merge Object.prototype values into iterable headers', function () {
        const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'Authorization');
        Object.prototype.Authorization = 'polluted';

        try {
          const headers = new AxiosHeaders(new Map([['Authorization', 'real']]));

          assert.strictEqual(headers.get('authorization'), 'real');
        } finally {
          descriptor
            ? Object.defineProperty(Object.prototype, 'Authorization', descriptor)
            : delete Object.prototype.Authorization;
        }
      });

      it('should support objects with an own iterator as a key-value source object', function () {
        const headers = new AxiosHeaders();

        headers.set({
          [Symbol.iterator]: function* () {
            yield ['x', '123'];
          }
        });

        assert.strictEqual(headers.get('x'), '123');
      });

      it('should not use inherited Symbol.iterator as a key-value source object', function () {
        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['x-app', 'changed'];
            yield ['x-injected', 'yes'];
          };

          const headers = new AxiosHeaders({
            'x-app': 'safe'
          });

          assert.strictEqual(headers.get('x-app'), 'safe');
          assert.strictEqual(headers.get('x-injected'), undefined);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should not read polluted Object.prototype Symbol.iterator accessors', function () {
        let accessed = false;

        try {
          Object.defineProperty(Object.prototype, Symbol.iterator, {
            configurable: true,
            get: function () {
              accessed = true;
              throw new Error('polluted iterator accessor');
            }
          });

          const headers = new AxiosHeaders({
            'x-app': 'safe'
          });

          assert.strictEqual(headers.get('x-app'), 'safe');
          assert.strictEqual(accessed, false);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should not consume an inherited Symbol.iterator for non-plain header sources', function () {
        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['x-injected', 'yes'];
            yield ['authorization', 'Bearer CHANGED'];
          };

          // A class instance and an Object.create(...) object both have a direct
          // prototype other than Object.prototype, yet their only iterator comes
          // from the polluted Object.prototype — they must not be iterated.
          class HeaderBag {
            constructor() {
              this['authorization'] = 'Bearer VALID';
            }
          }

          const fromClass = new AxiosHeaders(new HeaderBag());
          assert.strictEqual(fromClass.get('x-injected'), undefined);
          assert.notStrictEqual(fromClass.get('authorization'), 'Bearer CHANGED');

          const created = Object.create({ 'x-app': 'safe' });
          created['authorization'] = 'Bearer VALID';
          const fromCreate = new AxiosHeaders(created);
          assert.strictEqual(fromCreate.get('x-injected'), undefined);
          assert.notStrictEqual(fromCreate.get('authorization'), 'Bearer CHANGED');
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });

      it('should still merge duplicate keys from a genuine iterable source', function () {
        const headers = new AxiosHeaders(new Map());

        headers.set([
          ['x-multi', 'a'],
          ['x-multi', 'b']
        ]);

        assert.deepStrictEqual(headers.get('x-multi'), ['a', 'b']);
      });
    });

    describe('buildURL serializer options', function () {
      it('should ignore inherited serializer options', function () {
        let serializeInvoked = false;
        let encodeInvoked = false;

        Object.defineProperty(Object.prototype, 'serialize', {
          value: function () {
            serializeInvoked = true;
            return 'inherited=1';
          },
          configurable: true
        });
        Object.defineProperty(Object.prototype, 'encode', {
          value: function () {
            encodeInvoked = true;
            return 'inherited';
          },
          configurable: true
        });

        try {
          assert.strictEqual(buildURL('/foo', { value: 'a b' }, {}), '/foo?value=a+b');
          assert.strictEqual(serializeInvoked, false);
          assert.strictEqual(encodeInvoked, false);
        } finally {
          delete Object.prototype.serialize;
          delete Object.prototype.encode;
        }
      });

      it('should still honour an own serialize and an own encode', function () {
        assert.strictEqual(
          buildURL('/foo', { value: 'a b' }, { serialize: () => 'rendered' }),
          '/foo?rendered'
        );
        assert.strictEqual(
          buildURL('/foo', { value: 'a b' }, { encode: () => 'enc' }),
          '/foo?enc=enc'
        );
      });

      it('should still honour a function paramsSerializer shorthand', function () {
        assert.strictEqual(buildURL('/foo', { value: 'a b' }, () => 'rendered'), '/foo?rendered');
      });
    });

    describe('resolveConfig nested option gadgets', function () {
      it('should ignore inherited nested auth fields', function () {
        // resolveConfig's Basic-auth branch needs a global btoa (Node >= 16).
        if (typeof btoa === 'undefined') {
          this.skip();
          return;
        }

        Object.defineProperty(Object.prototype, 'username', {
          value: 'inherited-user',
          configurable: true,
          writable: true
        });
        Object.defineProperty(Object.prototype, 'password', {
          value: 'inherited-pass',
          configurable: true,
          writable: true
        });

        try {
          const resolved = resolveConfig({
            url: '/foo',
            auth: {}
          });

          assert.strictEqual(resolved.headers.get('Authorization'), 'Basic Og==');
        } finally {
          delete Object.prototype.username;
          delete Object.prototype.password;
        }
      });

      it('should still honour own nested auth fields', function () {
        // resolveConfig's Basic-auth branch needs a global btoa (Node >= 16).
        if (typeof btoa === 'undefined') {
          this.skip();
          return;
        }

        // `writable: true` matters: mergeConfig deep-copies the auth object, and a
        // non-writable Object.prototype.username would make that copy throw
        // regardless of the fix under test.
        Object.defineProperty(Object.prototype, 'username', {
          value: 'inherited-user',
          configurable: true,
          writable: true
        });

        try {
          const resolved = resolveConfig({
            url: '/foo',
            auth: { username: 'real', password: 'secret' }
          });

          assert.strictEqual(
            resolved.headers.get('Authorization'),
            'Basic ' + Buffer.from('real:secret').toString('base64')
          );
        } finally {
          delete Object.prototype.username;
        }
      });

      it('should ignore inherited nested serializer fields', function () {
        let serializeInvoked = false;
        let encodeInvoked = false;

        Object.defineProperty(Object.prototype, 'serialize', {
          value: function () {
            serializeInvoked = true;
            return 'inherited=1';
          },
          configurable: true
        });
        Object.defineProperty(Object.prototype, 'encode', {
          value: function () {
            encodeInvoked = true;
            return 'inherited';
          },
          configurable: true
        });

        try {
          const resolved = resolveConfig({
            url: '/foo',
            params: { value: 'a b' },
            paramsSerializer: {}
          });

          assert.strictEqual(resolved.url, '/foo?value=a+b');
          assert.strictEqual(serializeInvoked, false);
          assert.strictEqual(encodeInvoked, false);
        } finally {
          delete Object.prototype.serialize;
          delete Object.prototype.encode;
        }
      });

      it('should ignore an inherited params object', function () {
        Object.prototype.params = { injected: 'yes' };

        const resolved = resolveConfig({ url: '/foo' });

        assert.strictEqual(resolved.url, '/foo');
      });
    });

    describe('Axios bodyless method helpers', function () {
      it('should ignore inherited data for bodyless method helpers', async function () {
        this.timeout(10000);
        Object.defineProperty(Object.prototype, 'data', {
          value: 'inherited-body',
          configurable: true
        });

        try {
          for (const method of ['delete', 'get', 'head', 'options']) {
            let seenData = 'unset';

            await axios[method]('/test', {
              adapter: function (adapterConfig) {
                seenData = adapterConfig.data;

                return Promise.resolve({
                  data: null,
                  status: 200,
                  statusText: 'OK',
                  headers: {},
                  config: adapterConfig,
                  request: {}
                });
              }
            });

            assert.strictEqual(seenData, undefined, method + ' must not inherit data');
          }
        } finally {
          delete Object.prototype.data;
        }
      });

      it('should still forward own data passed to a bodyless method helper', async function () {
        this.timeout(10000);
        let seenData = 'unset';

        await axios.get('/test', {
          data: 'own-body',
          adapter: function (adapterConfig) {
            seenData = adapterConfig.data;

            return Promise.resolve({
              data: null,
              status: 200,
              statusText: 'OK',
              headers: {},
              config: adapterConfig,
              request: {}
            });
          }
        });

        assert.strictEqual(seenData, 'own-body');
      });

      it('should ignore inherited nested serializer fields in getUri', function () {
        let serializeInvoked = false;

        Object.defineProperty(Object.prototype, 'serialize', {
          value: function () {
            serializeInvoked = true;
            return 'inherited=1';
          },
          configurable: true
        });

        try {
          assert.strictEqual(
            axios.getUri({
              url: '/foo',
              params: { value: 'a b' },
              paramsSerializer: {}
            }),
            '/foo?value=a+b'
          );
          assert.strictEqual(serializeInvoked, false);
        } finally {
          delete Object.prototype.serialize;
        }
      });
    });

    describe('http adapter nested option gadgets', function () {
      it('should ignore inherited nested auth and serializer fields', async function () {
        this.timeout(10000);
        const server = await startServer();

        // `writable: true` matters: Node's URL parser assigns `username` on its
        // internal context object, which throws against a non-writable
        // Object.prototype.username on Node <= 16 regardless of the fix.
        Object.defineProperty(Object.prototype, 'username', {
          value: 'inherited-user',
          configurable: true,
          writable: true
        });
        Object.defineProperty(Object.prototype, 'password', {
          value: 'inherited-pass',
          configurable: true,
          writable: true
        });
        Object.defineProperty(Object.prototype, 'serialize', {
          value: function () {
            return 'inherited=1';
          },
          configurable: true,
          writable: true
        });

        try {
          const { port } = server.address();
          const res = await axios.get(`http://127.0.0.1:${port}/demo`, {
            auth: {},
            params: { value: 'a b' },
            paramsSerializer: {}
          });

          assert.strictEqual(res.data.headers.authorization, 'Basic Og==');
          assert.strictEqual(res.data.url, '/demo?value=a+b');
        } finally {
          delete Object.prototype.username;
          delete Object.prototype.password;
          delete Object.prototype.serialize;
          await stopServer(server);
        }
      });

      it('should ignore inherited proxy when the http adapter receives a plain config', async function () {
        this.timeout(10000);
        const proxyEnvKeys = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY'];
        const originalProxyEnv = Object.create(null);
        let proxyHits = 0;
        let targetHits = 0;

        for (const key of proxyEnvKeys) {
          originalProxyEnv[key] = process.env[key];
          delete process.env[key];
        }

        const proxy = await startServer((req, res) => {
          proxyHits += 1;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ via: 'proxy', url: req.url }));
        });
        const target = await startServer((req, res) => {
          targetHits += 1;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ via: 'target', url: req.url }));
        });

        try {
          Object.defineProperty(Object.prototype, 'proxy', {
            value: {
              protocol: 'http',
              host: '127.0.0.1',
              port: proxy.address().port
            },
            configurable: true
          });

          const response = await httpAdapter({
            method: 'get',
            url: `http://127.0.0.1:${target.address().port}/direct`,
            headers: {},
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0
          });
          const data = JSON.parse(response.data);

          assert.strictEqual(proxyHits, 0);
          assert.strictEqual(targetHits, 1);
          assert.deepStrictEqual(data, { via: 'target', url: '/direct' });
        } finally {
          delete Object.prototype.proxy;

          for (const key of proxyEnvKeys) {
            if (originalProxyEnv[key] === undefined) {
              delete process.env[key];
            } else {
              process.env[key] = originalProxyEnv[key];
            }
          }

          await stopServer(target);
          await stopServer(proxy);
        }
      });

      it('should ignore inherited paramsSerializer when the http adapter receives a plain config', async function () {
        this.timeout(10000);
        let serializerInvoked = false;

        Object.defineProperty(Object.prototype, 'paramsSerializer', {
          value: function () {
            serializerInvoked = true;
            return 'inherited=1';
          },
          configurable: true
        });

        const server = await startServer((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ url: req.url }));
        });

        try {
          const response = await httpAdapter({
            method: 'get',
            url: `http://127.0.0.1:${server.address().port}/direct`,
            headers: {},
            params: { value: 'a b' },
            proxy: false,
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0
          });
          const data = JSON.parse(response.data);

          assert.strictEqual(serializerInvoked, false);
          assert.deepStrictEqual(data, { url: '/direct?value=a+b' });
        } finally {
          delete Object.prototype.paramsSerializer;
          await stopServer(server);
        }
      });

      it('should ignore an inherited timeoutErrorMessage, decompress and maxContentLength', async function () {
        this.timeout(10000);
        Object.prototype.timeoutErrorMessage = 'inherited timeout message';
        Object.prototype.decompress = false;
        Object.prototype.maxContentLength = 1;

        const server = await startServer((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, padding: 'x'.repeat(64) }));
        });

        try {
          const { port } = server.address();
          const res = await httpAdapter({
            method: 'get',
            url: `http://127.0.0.1:${port}/api`,
            headers: {},
            proxy: false,
            maxRedirects: 0,
            maxContentLength: -1,
            maxBodyLength: -1,
            timeout: 0
          });

          // A polluted maxContentLength of 1 would have rejected this response.
          assert.strictEqual(res.status, 200);
          assert.ok(res.data.length > 1);
        } finally {
          await stopServer(server);
        }
      });

      it('should not use an inherited Symbol.iterator for request or response headers', async function () {
        this.timeout(10000);
        let capturedHeaders;
        const stubTransport = {
          request(options, handleResponse) {
            capturedHeaders = { ...options.headers };
            const req = new EventEmitter();
            req.write = () => true;
            req.setTimeout = () => {};
            req.destroy = () => {};
            req.end = () => {
              const res = new stream.Readable({ read() {} });
              res.statusCode = 200;
              res.statusMessage = 'OK';
              res.headers = { 'x-server': 'real' };
              res.rawHeaders = [];
              res.req = req;
              process.nextTick(() => {
                handleResponse(res);
                res.push(null);
              });
            };
            return req;
          }
        };

        try {
          Object.prototype[Symbol.iterator] = function* () {
            yield ['X-Injected', 'yes'];
            yield ['Authorization', 'Bearer CHANGED'];
          };

          const response = await axios.get('http://stub.invalid/', {
            headers: {
              Authorization: 'Bearer VALID_USER_TOKEN',
              'X-App': 'safe'
            },
            transport: stubTransport,
            maxRedirects: 0
          });

          assert.ok(capturedHeaders, 'transport was not invoked');
          assert.strictEqual(capturedHeaders['X-App'], 'safe');
          assert.strictEqual(
            capturedHeaders.Authorization || capturedHeaders.authorization,
            'Bearer VALID_USER_TOKEN'
          );
          assert.strictEqual(
            capturedHeaders['X-Injected'] || capturedHeaders['x-injected'],
            undefined
          );
          assert.strictEqual(response.headers.get('x-server'), 'real');
          assert.strictEqual(response.headers.get('x-injected'), undefined);
        } finally {
          delete Object.prototype[Symbol.iterator];
        }
      });
    });
  });

});
