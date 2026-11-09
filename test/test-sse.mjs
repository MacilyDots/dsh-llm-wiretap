// 离线验证 analyzeSse：两种协议的统计口径。
import assert from "node:assert/strict";
import { analyzeSse } from "../lib/sse.js";

function anthropicSse(bodyLines) {
  return bodyLines.map((line) => "event: " + JSON.parse(line).type + "\n" + "data: " + line + "\n\n").join("");
}

// ── 1. Anthropic 退化形态：reasoning 反复吐同一短句 ──────────────────
const degenerate = [];
degenerate.push(JSON.stringify({ type: "message_start", message: { id: "msg_1", model: "deepseek-flash" } }));
degenerate.push(JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "" } }));
for (let i = 0; i < 300; i += 1) {
  degenerate.push(JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "做。\n" } }));
}
degenerate.push(JSON.stringify({ type: "message_delta", delta: { stop_reason: "max_tokens" } }));

const bad = analyzeSse(anthropicSse(degenerate));
assert.equal(bad.frames, 303);
assert.equal(bad.messageId, "msg_1");
assert.equal(bad.model, "deepseek-flash");
assert.equal(bad.maxRepeat, 300, "300 次「做。」必须被统计成 300");
assert.equal(bad.maxRepeatLine, "做。");
assert.equal(bad.stopReason, "max_tokens");
assert.equal(bad.toolBlocks, 0);
assert.equal(bad.reasoningChars, 300 * 3);
assert.equal(bad.hasStructuralTopLine, false);

// ── 2. 正常步：thinking + 正文 + 工具调用 ───────────────────────────
const healthy = [];
healthy.push(JSON.stringify({ type: "message_start", message: { id: "msg_2", model: "deepseek-flash" } }));
healthy.push(JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "" } }));
healthy.push(JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "先看目录。\n再读文件。\n" } }));
healthy.push(JSON.stringify({ type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "toolu_1", name: "read", input: {} } }));
healthy.push(JSON.stringify({ type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"file_path":"x"}' } }));
healthy.push(JSON.stringify({ type: "message_delta", delta: { stop_reason: "tool_use" } }));

const good = analyzeSse(anthropicSse(healthy));
assert.equal(good.maxRepeat, 1);
assert.equal(good.toolBlocks, 1);
assert.equal(good.toolDeltas, 1);
assert.equal(good.stopReason, "tool_use");
assert.equal(good.textChars, 0);

// ── 3. OpenAI Completions 形态 ──────────────────────────────────────
const openai = [
  JSON.stringify({ id: "c1", model: "minimax-m3", choices: [{ delta: { reasoning_content: "好。\n" } }] }),
  JSON.stringify({ id: "c1", model: "minimax-m3", choices: [{ delta: { reasoning_content: "好。\n" } }] }),
  JSON.stringify({ id: "c1", model: "minimax-m3", choices: [{ delta: { reasoning_content: "好。\n" } }] }),
  JSON.stringify({ id: "c1", model: "minimax-m3", choices: [{ delta: { content: "完成" }, finish_reason: "stop" }] }),
]
  .map((line) => "data: " + line + "\n\n")
  .join("");
const mini = analyzeSse(openai);
assert.equal(mini.frames, 4);
assert.equal(mini.maxRepeat, 3);
assert.equal(mini.maxRepeatLine, "好。");
assert.equal(mini.textChars, 2);
assert.equal(mini.stopReason, "stop");
assert.equal(mini.model, "minimax-m3");

// ── 4. 坏帧与纯结构行 ──────────────────────────────────────────────
const messy =
  "data: not-json\n\n" +
  "data: " + JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "```\n```\n```\n" } }) + "\n\n";
const m = analyzeSse(messy);
assert.equal(m.malformedFrames, 1);
assert.equal(m.maxRepeat, 3);
assert.equal(m.hasStructuralTopLine, true, "``` 是结构行，必须被标记出来");

console.log("test-sse: 4 组断言全部通过");
