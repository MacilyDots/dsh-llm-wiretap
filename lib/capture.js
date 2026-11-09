/* dsh-llm-wiretap — 落盘层。
 *
 * 每个被捕获的 Messages/Completions 请求一个目录：
 *   <dshHome>/logs/wiretap/<id>/
 *     request.json   适配器实际发出的 body 原文（实验 2 的采样参数直接从这里读）
 *     response.sse   上游原始 SSE 文本（无损，截断时在 meta 里标记）
 *     meta.json      元数据 + 解析统计（analyzeSse 的结果）
 *
 * 保留策略：只保留最近 `keep` 个请求目录，老的整目录删除。
 * 所有 IO 失败都吞掉并计入 errors——记录器绝不能影响请求本身。
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { analyzeSse } from "./sse.js";

const MAX_KEEP = 200;

/** 需要脱敏的请求头（值不入盘，只留长度）。 */
const SECRET_HEADERS = /^(authorization|x-api-key|x-dsh-auth-token|cookie|proxy-authorization)$/i;

function stamp(date) {
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  return (
    String(date.getFullYear()) +
    pad(date.getMonth() + 1) +
    pad(date.getDate()) +
    "T" +
    pad(date.getHours()) +
    pad(date.getMinutes()) +
    pad(date.getSeconds()) +
    "." +
    pad(date.getMilliseconds(), 3)
  );
}

/** 把 Headers / 普通对象统一成 [name, value] 列表。 */
function headerEntries(headers) {
  if (headers === undefined || headers === null) return [];
  if (typeof headers.entries === "function") return [...headers.entries()];
  if (typeof headers === "object") return Object.entries(headers).filter(([, v]) => typeof v === "string");
  return [];
}

/**
 * @param {{ dshHome: string, keep?: number, maxBytes?: number, pinRepeat?: number }} options
 */
export function createCapture({ dshHome, keep = 12, maxBytes = 16 * 1024 * 1024, pinRepeat = 100 }) {
  const root = join(dshHome, "logs", "wiretap");
  const cappedKeep = Math.min(Math.max(1, keep), MAX_KEEP);
  let counter = 0;
  let lastId = "";
  let lastDir = "";
  const errors = [];
  const state = { captured: 0, skipped: 0, truncated: 0, pinned: 0, ioErrors: 0 };

  function noteError(stage, error) {
    state.ioErrors += 1;
    errors.push({ at: Date.now(), stage, message: String(error?.message ?? error) });
    if (errors.length > 20) errors.shift();
  }

  function retain() {
    try {
      const entries = readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory());
      const names = entries.map((entry) => entry.name).sort();
      const pinned = new Set();
      for (const name of names) {
        try {
          if (existsSync(join(root, name, "pinned"))) pinned.add(name);
        } catch {
          /* ignore */
        }
      }
      const removable = names.filter((name) => !pinned.has(name));
      for (const name of removable.slice(0, Math.max(0, removable.length - cappedKeep))) {
        rmSync(join(root, name), { recursive: true, force: true });
      }
    } catch (error) {
      noteError("retain", error);
    }
  }

  /**
   * 开始捕获一个请求。返回的 record 在流结束（或出错）时 push 字节、再 finish。
   *
   * @param {{
   *   url: string,
   *   method: string,
   *   requestHeaders: unknown,
   *   requestBody: unknown,
   *   status: number,
   *   responseHeaders: unknown,
   *   startedAt: number,
   *   headersAt: number,
   * }} input
   */
  function begin(input) {
    counter += 1;
    const date = new Date(input.startedAt);
    const id = stamp(date) + "-" + String(counter).padStart(3, "0");
    const dir = join(root, id);
    // 请求体有两种来源：同步拿到的字符串，或 Request.clone().text() 的 Promise。
    let bodyText = null;
    let bodyNote = "";
    if (typeof input.requestBody === "string") {
      bodyText = input.requestBody;
    } else if (input.requestBody === undefined || input.requestBody === null) {
      bodyNote = "pending-or-absent";
    } else if (Object.prototype.toString.call(input.requestBody) === "[object Object]") {
      // 有些适配器直接传对象而不是已序列化的字符串；照样留一份，实验 2 才有参数可读。
      try {
        bodyText = JSON.stringify(input.requestBody);
      } catch {
        bodyNote = "unserializable-object";
      }
    } else {
      bodyNote = "non-string-body(" + Object.prototype.toString.call(input.requestBody) + ")";
    }
    const requestHeaders = {};
    for (const [name, value] of headerEntries(input.requestHeaders)) {
      requestHeaders[name] = SECRET_HEADERS.test(name) ? "<redacted len=" + String(value).length + ">" : String(value);
    }
    const responseHeaders = {};
    for (const [name, value] of headerEntries(input.responseHeaders)) responseHeaders[name] = String(value);

    const sessionId = requestHeaders["x-deepseek-harness-session-id"] ?? "";

    try {
      mkdirSync(dir, { recursive: true });
      if (bodyText !== null) writeFileSync(join(dir, "request.json"), bodyText);
    } catch (error) {
      noteError("begin", error);
    }
    lastId = id;
    lastDir = dir;
    state.captured += 1;

    const chunks = [];
    let received = 0;
    let truncated = false;
    let finished = false;

    return {
      id,
      dir,
      sessionId: typeof sessionId === "string" ? sessionId : "",
      /** 请求体是流时，异步补写（Request.clone().text() 的结果）。 */
      attachBody(text) {
        if (typeof text !== "string" || text === "") return;
        if (bodyText !== null) return;
        bodyText = text;
        bodyNote = "";
        try {
          writeFileSync(join(dir, "request.json"), text);
        } catch (error) {
          noteError("attachBody", error);
        }
      },
      /** 原始字节落到内存（有上限），finish 时一次性解析并写盘。 */
      push(bytes) {
        if (finished || truncated) return;
        if (received + bytes.byteLength > maxBytes) {
          truncated = true;
          state.truncated += 1;
          return;
        }
        received += bytes.byteLength;
        chunks.push(Buffer.from(bytes));
      },
      /**
       * 结束并落盘。是异步的：Request 形态下请求体要等 clone().text() 完成，
       * 否则会在流结束时丢掉 requestChars 与 request.json。
       * @param {{ completed: boolean, error?: string, endedAt: number }} outcome
       */
      async finish(outcome) {
        if (finished) return;
        finished = true;
        if (bodyText === null && input.requestBodyPromise !== undefined) {
          try {
            const late = await input.requestBodyPromise;
            if (typeof late === "string" && late !== "") {
              bodyText = late;
              bodyNote = "";
              try {
                writeFileSync(join(dir, "request.json"), late);
              } catch (error) {
                noteError("late-body", error);
              }
            }
          } catch {
            bodyNote = "body-unavailable";
          }
        }
        const bytes = Buffer.concat(chunks);
        const text = bytes.toString("utf8");
        let sse = null;
        try {
          sse = analyzeSse(text);
        } catch (error) {
          noteError("analyze", error);
        }
        const meta = {
          id,
          sessionId: typeof sessionId === "string" ? sessionId : "",
          url: String(input.url),
          method: String(input.method),
          status: input.status,
          requestHeaders,
          responseHeaders,
          bodyNote: bodyNote === "" ? undefined : bodyNote,
          requestChars: bodyText === null ? 0 : bodyText.length,
          timing: {
            startedAt: input.startedAt,
            headersAt: input.headersAt,
            endedAt: outcome.endedAt,
            headersMs: input.headersAt - input.startedAt,
            streamMs: outcome.endedAt - input.headersAt,
          },
          rawBytes: bytes.byteLength,
          truncated,
          // DSH 读完流会立刻 abort，clone 出来的旁路分支于是收到 "This operation was aborted"。
          // 所以「传输层被中止」不等于「数据不完整」：只要 SSE 里有终止帧，就按完整记录。
          completed: outcome.completed === true || (sse?.types?.["message_stop"] ?? 0) > 0,
          transportAborted: outcome.completed !== true,
          error: outcome.error,
          sse,
        };
        try {
          writeFileSync(join(dir, "response.sse"), text);
          writeFileSync(join(dir, "meta.json"), JSON.stringify(meta, null, 2));
          // 重复达到阈值或只有 reasoning 而无可见正文/工具调用：这两类记录都必须留着。
          const reasoningOnly =
            (sse?.reasoningChars ?? 0) > 0 &&
            (sse?.textChars ?? 0) === 0 &&
            (sse?.toolBlocks ?? 0) === 0;
          if ((sse?.maxRepeat ?? 0) >= pinRepeat || reasoningOnly) {
            writeFileSync(join(dir, "pinned"), reasoningOnly ? "reasoning-only" : String(sse.maxRepeat));
            meta.pinned = true;
            meta.pinReason = reasoningOnly ? "reasoning-only" : "repeat-threshold";
            state.pinned += 1;
            writeFileSync(join(dir, "meta.json"), JSON.stringify(meta, null, 2));
          }
        } catch (error) {
          noteError("finish", error);
        }
        retain();
      },
    };
  }

  function recent(limit = 10) {
    try {
      const dirs = readdirSync(root, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort()
        .slice(-limit)
        .reverse();
      return dirs.map((name) => {
        let meta = null;
        try {
          meta = JSON.parse(readFileSync(join(root, name, "meta.json"), "utf8"));
        } catch {
          /* 未完成的请求没有 meta */
        }
        return { id: name, dir: join(root, name), meta };
      });
    } catch {
      return [];
    }
  }

  return {
    root,
    begin,
    recent,
    state: () => ({ ...state, lastId, lastDir, errors: errors.slice() }),
    clear() {
      try {
        rmSync(root, { recursive: true, force: true });
        return true;
      } catch (error) {
        noteError("clear", error);
        return false;
      }
    },
  };
}
