/* dsh-llm-wiretap — 宿主半。
 *
 * 问题：dsh-degen-guard 能证明「退化发生在工具调用之前」，但证明不了
 * 「重复到底是模型/上游吐出来的，还是 DSH 处理出来的」。两者的分界线是
 * 适配器收到的那串上游原始字节。
 *
 * 做法：在本进程里包装一次 globalThis.fetch，只拦截「POST + accept:
 * text/event-stream + JSON body」的 Messages / Completions 请求：
 *   1. 落盘请求体（实验 2 要看实际生效的采样参数）；
 *   2. 用 body.tee() 旁路复制上游原始字节 → response.sse（无损）；
 *   3. 用 dsh-degen-guard 同一套行重复口径统计原始流，写进 meta.json。
 *
 * 只读：不改请求、不改响应、不注入头。记录器自身任何异常都吞掉继续放行。
 * 原始流里 maxRepeat >= pinRepeat 的请求会被钉住（不参与轮转删除），
 * 因为退化一旦发生，下一次请求就会把 ring buffer 冲掉。
 *
 * 路由：
 *   GET  /dsh-llm-wiretap/recent?limit=N   最近 N 个捕获目录（含统计）
 *   GET  /dsh-llm-wiretap/stats            本进程计数与最近错误
 *   POST /dsh-llm-wiretap/clear            清空捕获目录
 */
import { appendFileSync, mkdirSync, statSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createCapture } from "./capture.js";

export const name = "dsh-llm-wiretap";

const ROUTE_PREFIX = "/dsh-llm-wiretap";
const MAX_LOG_BYTES = 512 * 1024;
/** 同一进程内只允许一层拦截；重载时用这个标记防重复包装。 */
const PATCHED = Symbol.for("dsh-llm-wiretap.patched");

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), ".dsh");
}

function logPath() {
  return join(dshHome(), "logs", "dsh-llm-wiretap.log");
}

/** Append one line with a single rotation; never throws. */
function appendLog(line) {
  try {
    const dir = join(dshHome(), "logs");
    mkdirSync(dir, { recursive: true });
    const file = logPath();
    try {
      if (statSync(file).size > MAX_LOG_BYTES) renameSync(file, file + ".1");
    } catch {
      /* missing file — append below still works */
    }
    appendFileSync(file, line + "\n");
  } catch {
    /* logging must never break the plugin */
  }
}

export const DEFAULT_CONFIG = {
  enabled: true,
  /** 保留多少个未钉住的请求目录。 */
  keep: 50,
  /** 单个请求最多记录多少字节原始流；超出部分丢弃并标记 truncated。 */
  maxBytes: 16 * 1024 * 1024,
  /** 原始流同句重复达到这个次数就钉住该请求（与 degen-guard 的阈值同源）。 */
  pinRepeat: 100,
};

export function resolveConfig(raw) {
  const out = { ...DEFAULT_CONFIG };
  if (raw === null || typeof raw !== "object") return out;
  if (typeof raw.enabled === "boolean") out.enabled = raw.enabled;
  if (Number.isInteger(raw.keep) && raw.keep > 0) out.keep = raw.keep;
  if (Number.isInteger(raw.maxBytes) && raw.maxBytes > 0) out.maxBytes = raw.maxBytes;
  if (Number.isInteger(raw.pinRepeat) && raw.pinRepeat > 0) out.pinRepeat = raw.pinRepeat;
  return out;
}

/** 解析 Headers / Request.headers / 普通对象成 Map（小写名）。 */
function headerMap(headers) {
  const map = new Map();
  if (headers === undefined || headers === null) return map;
  if (typeof headers.entries === "function") {
    for (const [name, value] of headers.entries()) map.set(String(name).toLowerCase(), String(value));
    return map;
  }
  if (typeof headers === "object") {
    for (const [name, value] of Object.entries(headers)) {
      if (typeof value === "string") map.set(name.toLowerCase(), value);
    }
  }
  return map;
}

/** 只有 POST 流式 JSON 的 Messages / Completions 请求才值得记录。 */
function shouldTap(input, init) {
  const method = String(init?.method ?? (typeof input === "object" && input !== null ? input.method : "GET")).toUpperCase();
  if (method !== "POST") return false;
  let url;
  if (typeof input === "string") url = input;
  else if (input instanceof URL) url = input.href;
  else if (input !== null && typeof input === "object" && typeof input.url === "string") url = input.url;
  else return false;
  const path = url.split("?")[0];
  if (!/\/(messages|chat\/completions)$/.test(path)) return false;
  const headers = headerMap(init?.headers ?? (input !== null && typeof input === "object" ? input.headers : undefined));
  if (!/text\/event-stream/i.test(headers.get("accept") ?? "")) return false;
  if (!/application\/json/i.test(headers.get("content-type") ?? "")) return false;
  return true;
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(body);
}

export function apply(ctx, rawConfig) {
  const config = resolveConfig(rawConfig);
  const capture = createCapture({
    dshHome: dshHome(),
    keep: config.keep,
    maxBytes: config.maxBytes,
    pinRepeat: config.pinRepeat,
  });
  const stats = { intercepted: 0, tapped: 0, failed: 0, headersOnly: 0 };

  // ── fetch 拦截 ────────────────────────────────────────────────────
  // ctx.effect 的返回值在插件卸载时执行；恢复原 fetch 只在「当前还是我们的
  // 包装函数」时进行，避免覆盖掉后加载的其它包装。
  ctx.effect(() => {
    if (!config.enabled) return () => {};
    const original = globalThis.fetch;
    if (typeof original !== "function") {
      appendLog(new Date().toISOString() + " host-warn fetch is not a function; wiretap disabled");
      return () => {};
    }
    if (original[PATCHED] === true) {
      appendLog(new Date().toISOString() + " host-warn fetch already patched by another wiretap instance");
      return () => {};
    }

    const patched = async function wiretapFetch(input, init) {
      stats.intercepted += 1;
      if (!shouldTap(input, init)) return original.call(globalThis, input, init);

      const startedAt = Date.now();
      // 必须在 fetch 消费请求体之前 clone，否则 clone 会因 body 已 disturbed 抛 "unusable"。
      const method = String(init?.method ?? (typeof input === "object" && input !== null ? input.method : "POST"));
      const url = typeof input === "string" ? input : (input?.url ?? String(input));
      // 0.2.1 起 DSH 用 Request 对象调 fetch，init 为空——headers 必须从 input 上取，
      // 否则 sessionId（x-deepseek-harness-session-id）会丢，三层对照就无法对齐会话日志。
      const sourceHeaders =
        init?.headers ?? (input !== null && typeof input === "object" && input.headers !== undefined ? input.headers : undefined);
      // 请求体同样要在 fetch 之前取：Request 的 body 是流，必须同步 clone。
      // 若把 clone() 放进微任务，original.fetch 可能先消费 body，随后 clone 会失败。
      let bodyClone;
      if (
        (init?.body === undefined || init?.body === null) &&
        input !== null &&
        typeof input === "object" &&
        typeof input.clone === "function" &&
        input.bodyUsed !== true
      ) {
        try {
          bodyClone = input.clone();
        } catch {
          /* 已被更外层包装器消费时无法再克隆 */
        }
      }
      const bodyPromise =
        init?.body !== undefined && init?.body !== null
          ? Promise.resolve(init.body)
          : bodyClone
            ? bodyClone.text().catch(() => undefined)
            : Promise.resolve(undefined);

      const response = await original.call(globalThis, input, init);
      const headersAt = Date.now();
      if (response === null || typeof response !== "object" || response.body === null) {
        stats.headersOnly += 1;
        return response;
      }

      try {
        const record = capture.begin({
          url,
          method,
          requestHeaders: sourceHeaders,
          requestBody: undefined,
          // finish 会 await 它，把 Request 形态下的请求体补进 request.json 与 requestChars。
          requestBodyPromise: bodyPromise,
          status: response.status,
          responseHeaders: response.headers,
          startedAt,
          headersAt,
        });
        stats.tapped += 1;
        // 前几次捕获写入诊断：确认 fetch 被调用时的真实入参形态，避免再盲改。
        if (stats.tapped <= 3) {
          const headerKeys =
            sourceHeaders === undefined
              ? "none"
              : typeof sourceHeaders.keys === "function"
                ? [...sourceHeaders.keys()].join(",")
                : Object.keys(sourceHeaders).join(",");
          appendLog(
            new Date().toISOString() +
              " diag " +
              JSON.stringify({
                inputType: typeof input,
                isRequest: input instanceof Request,
                hasInit: init !== undefined && init !== null,
                initKeys: init === undefined || init === null ? "none" : Object.keys(init).join(","),
                headerKeys,
                sessionId: record.sessionId,
              }),
          );
        }

        // clone() 内部就是 tee，但保留了 status/headers 的全部语义；
        // 手动 new Response 会在 content-encoding 这类头上留坑。
        const copy = response.clone();
        // 旁路消费：不 await，绝不能拖慢消费者。
        void pump(copy.body, record);
        return response;
      } catch (error) {
        stats.failed += 1;
        appendLog(new Date().toISOString() + " tap-failed " + JSON.stringify({ message: String(error?.message ?? error) }));
        // tee 之前失败：原 response 已返回给调用方？不，我们还没返回。
        // 这里 response.body 还没被消费，直接原样返回是安全的。
        return response;
      }
    };
    patched[PATCHED] = true;

    globalThis.fetch = patched;
    appendLog(
      new Date().toISOString() +
        " host-ready " +
        JSON.stringify({ version: "0.1.2", root: capture.root, keep: config.keep, pinRepeat: config.pinRepeat, maxBytes: config.maxBytes }),
    );
    return () => {
      if (globalThis.fetch === patched) globalThis.fetch = original;
    };
  }, "dsh-llm-wiretap: fetch interceptor");

  // ── 诊断路由 ──────────────────────────────────────────────────────
  ctx.inject(["webServer"], (host) => {
    host.effect(() => {
      const disposers = [];

      const recentHandler = (req, res) => {
        if (req.method !== "GET") {
          res.writeHead(405);
          res.end();
          return;
        }
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 10) || 10, 1), 50);
        sendJson(res, 200, { ok: true, root: capture.root, state: capture.state(), stats, recent: capture.recent(limit) });
      };

      const statsHandler = (req, res) => {
        if (req.method !== "GET") {
          res.writeHead(405);
          res.end();
          return;
        }
        sendJson(res, 200, { ok: true, enabled: config.enabled, root: capture.root, stats, state: capture.state() });
      };

      const clearHandler = (req, res) => {
        if (req.method !== "POST") {
          res.writeHead(405);
          res.end();
          return;
        }
        sendJson(res, 200, { ok: capture.clear() });
      };

      disposers.push(host.webServer.register({ kind: "exact", path: ROUTE_PREFIX + "/recent", handler: recentHandler }));
      disposers.push(host.webServer.register({ kind: "exact", path: ROUTE_PREFIX + "/stats", handler: statsHandler }));
      disposers.push(host.webServer.register({ kind: "exact", path: ROUTE_PREFIX + "/clear", handler: clearHandler }));

      return () => {
        for (const dispose of disposers) {
          try {
            dispose();
          } catch {
            /* ignore */
          }
        }
      };
    }, "dsh-llm-wiretap: diagnostics routes");
  });
}

/** 旁路消费 tee 出来的那份流，写进 capture 记录。绝不向外抛错。 */
async function pump(stream, record) {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value !== undefined && value !== null) record.push(value);
    }
    await record.finish({ completed: true, endedAt: Date.now() });
  } catch (error) {
    await record.finish({ completed: false, error: String(error?.message ?? error), endedAt: Date.now() });
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }
}
