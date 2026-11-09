// 回归测试：fetch 只收到 Request 对象（init 为空）时，headers 与会话 id 仍要捕获。
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const sandbox = mkdtempSync(join(tmpdir(), "wiretap-req-"));
process.env.DSH_HOME = sandbox;

const { apply } = await import("../lib/index.js");

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
  inject() {},
};

const sseBody =
  'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_req","model":"deepseek-flash"}}\n\n' +
  'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}\n\n' +
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"做。\\n做。\\n"}}\n\n' +
  'event: message_stop\ndata: {"type":"message_stop"}\n\n';

const requestBody = JSON.stringify({ model: "deepseek-flash", max_tokens: 256000, output_config: { effort: "high" } });

const originalFetch = globalThis.fetch;
const mockFetch = async (input) => {
  // 断言调用方确实只传了 Request 对象，没有 init —— 复现 0.2.1 的调用形态。
  assert.ok(input instanceof Request, "调用方应传 Request 对象");
  return new Response(sseBody, { status: 200, headers: { "content-type": "text/event-stream" } });
};
globalThis.fetch = mockFetch;

apply(ctx, { enabled: true, keep: 3, pinRepeat: 100 });

// 用 Request 对象发起：headers 与 body 都挂在 Request 上。
const request = new Request("https://api.deepseek.com/anthropic/v1/messages", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    accept: "text/event-stream",
    "x-deepseek-harness-session-id": "session-request-object",
    "x-api-key": "SECRET-KEY-abcdefghijklmn",
  },
  body: requestBody,
});

const res = await globalThis.fetch(request);
const consumed = await res.text();
assert.equal(consumed, sseBody, "消费者读到的流不被改写");

const root = join(sandbox, "logs", "wiretap");
const waitFor = async () => {
  for (let i = 0; i < 200; i += 1) {
    const names = readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
    if (names.length > 0 && existsSync(join(root, names[names.length - 1], "meta.json"))) return join(root, names[names.length - 1]);
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("meta.json 未写出");
};
const dir = await waitFor();
const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));

assert.equal(meta.sessionId, "session-request-object", "sessionId 必须能从 Request.headers 取到");
assert.equal(meta.requestHeaders["x-deepseek-harness-session-id"], "session-request-object");
assert.equal(meta.requestHeaders["x-api-key"], "<redacted len=25>", "凭据仍需脱敏");
assert.ok(!JSON.stringify(meta).includes("SECRET-KEY"), "meta 里不能出现凭据原文");
assert.equal(meta.requestChars, requestBody.length, "请求体应从 Request.clone() 补写");

assert.ok(existsSync(join(dir, "request.json")), "request.json 应存在");
const savedBody = JSON.parse(readFileSync(join(dir, "request.json"), "utf8"));
assert.equal(savedBody.max_tokens, 256000, "请求体内容应完整");

for (const dispose of cleanups) dispose();
assert.equal(globalThis.fetch, mockFetch, "卸载后应恢复原 fetch");
globalThis.fetch = originalFetch;
rmSync(sandbox, { recursive: true, force: true });
console.log("test-request-object: 全部断言通过（Request 形态的 headers/body 均被捕获）");
