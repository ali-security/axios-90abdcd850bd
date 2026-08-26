"use strict";

import assert from "assert";
import http from "http";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import httpAdapter from "../../../lib/adapters/http.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";

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
});
