// 离线验证插件整体行为：mock fetch → 落盘 → 消费者拿到的流不变 → 脱敏 → 钉住。
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const sandbox = mkdtempSync(join(tmpdir(), "wiretap-test-"));
process.env.DSH_HOME = sandbox;

const { apply } = await import("../lib/index.js");

// ── mock 宿主 ctx：effect 立即执行并返回清理函数，inject 不触发 ──────
const cleanups = [];
const ctx = {
  on() {
    throw new Error("wiretap 不应注册 agent 事件");
  },
  effect(fn) {
    const dispose = fn();
    if (typeof dispose === "function") cleanups.push(dispose);
    return dispose;
  },
  inject() {
    /* webServer 不存在时插件必须仍然加载 */
  },
};

// ── 构造上游 SSE ───────────────────────────────────────────────────
const repeat = 150;
const sseBody =
  'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_test","model":"deepseek-flash"}}\n\n' +
  'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}\n\n' +
  Array.from({ length: repeat })
    .map(
      (_, i) =>
        "event: content_block_delta\ndata: " +
        JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: i === 0 ? "做。" : "\n做。" } }) +
        "\n\n",
    )
    .join("") +
  'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"max_tokens"}}\n\n';

let fetched = 0;
const originalFetch = globalThis.fetch;
/** 被测插件会包装这个 mock；卸载后必须恢复成它本身。 */
const mockFetch = async (input, init) => {
  fetched += 1;
  const url = typeof input === "string" ? input : input.url;
  if ((init?.method ?? "POST") === "POST") assert.match(url, /\/messages$/);
  return new Response(sseBody, {
    status: 200,
    headers: { "content-type": "text/event-stream", "x-request-id": "req_abc" },
  });
};
globalThis.fetch = mockFetch;

apply(ctx, { enabled: true, keep: 2, pinRepeat: 100 });

// ── 1. 必须拦截的请求 ──────────────────────────────────────────────
const requestBody = JSON.stringify({
  model: "deepseek-flash",
  stream: true,
  max_tokens: 256000,
  thinking: { type: "enabled" },
  output_config: { effort: "high" },
  messages: [{ role: "user", content: [{ type: "text", text: "继续" }] }],
});
const res = await globalThis.fetch("https://api.deepseek.com/anthropic/v1/messages", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    accept: "text/event-stream",
    "x-dsh-auth-token": "SECRET-TOKEN-VALUE-1234567890",
    "x-deepseek-harness-session-id": "session-test-1",
  },
  body: requestBody,
});

// 消费者拿到的字节必须与上游完全一致（tee 不能改写）
const consumed = await res.text();
assert.equal(consumed, sseBody, "消费者读到的流必须与原始流逐字节一致");
assert.equal(res.headers.get("x-request-id"), "req_abc", "响应头必须保留");

// ── 等待旁路落盘 ───────────────────────────────────────────────────
const root = join(sandbox, "logs", "wiretap");
function dirNames() {
  try {
    return readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
}
for (let i = 0; i < 200; i += 1) {
  const names = dirNames();
  if (names.length > 0 && existsSync(join(root, names[names.length - 1], "meta.json"))) break;
  await new Promise((r) => setTimeout(r, 20));
}
const names = dirNames();
assert.ok(names.length > 0, "必须落盘至少一个捕获目录");
const dir = join(root, names[names.length - 1]);
assert.ok(existsSync(join(dir, "meta.json")), "旁路必须写出 meta.json");

const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));
assert.equal(meta.sessionId, "session-test-1", "sessionId 必须从 x-deepseek-harness-session-id 提取");
assert.equal(meta.status, 200);
assert.equal(meta.completed, true, "流正常结束应标记 completed");
assert.equal(meta.truncated, false);
assert.equal(meta.requestHeaders["x-dsh-auth-token"], "<redacted len=29>", "凭据必须脱敏");
assert.ok(!JSON.stringify(meta).includes("SECRET-TOKEN-VALUE"), "meta 中绝不能出现凭据原文");
assert.equal(meta.sse.maxRepeat, repeat, "原始流重复度必须与上游一致");
assert.equal(meta.sse.maxRepeatLine, "做。");
assert.equal(meta.sse.stopReason, "max_tokens");
assert.equal(meta.sse.model, "deepseek-flash");
assert.ok(meta.pinned === true, "maxRepeat>=pinRepeat 时应钉住");
assert.ok(existsSync(join(dir, "pinned")), "pinned 标记文件必须存在");

const raw = readFileSync(join(dir, "response.sse"), "utf8");
assert.equal(raw, sseBody, "原始 SSE 必须无损落盘");

const savedRequest = JSON.parse(readFileSync(join(dir, "request.json"), "utf8"));
assert.equal(savedRequest.max_tokens, 256000, "请求体里的实际参数必须原样落盘");
assert.equal(savedRequest.output_config.effort, "high");

// ── 2. 不该拦截的请求：非流式 / 非 messages ────────────────────────
const plain = await globalThis.fetch("https://api.deepseek.com/v1/models", { method: "GET" });
assert.equal(plain.status, 200);
assert.equal(readdirSync(root).filter((n) => existsSync(join(root, n, "meta.json"))).length, 1, "非流式请求不得产生捕获");

// ── 3. 卸载时恢复原 fetch ──────────────────────────────────────────
for (const dispose of cleanups) dispose();
assert.equal(globalThis.fetch, mockFetch, "清理时必须恢复被包装的那个 fetch");

globalThis.fetch = originalFetch;
rmSync(sandbox, { recursive: true, force: true });
console.log("test-wiretap: 全部断言通过（捕获 " + fetched + " 次 fetch，落盘 1 个请求）");
