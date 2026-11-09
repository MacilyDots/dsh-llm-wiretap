/* dsh-llm-wiretap — 原始 SSE 解析（纯函数，可离线测试）。
 *
 * 输入是适配器收到之前的「上游原始字节」解码后的文本，输出是事件列表与统计，
 * 用于和 DSH 会话日志里最终拼接的 reasoning 逐项比对：
 *   - 原始流里是否已经出现「做。」×100+  → 重复在上游生成
 *   - 原始流正常但会话日志重复           → 适配器/拼接/记录层
 *
 * 同时兼容两种协议（见 lib/index.js 的 URL 判定）：
 *   Anthropic Messages：event: xxx / data: {"type":"content_block_delta", "delta":{"type":"thinking_delta","thinking":"…"}}
 *   OpenAI Completions：data: {"choices":[{"delta":{"content":"…","reasoning_content":"…"}}]}
 */

/** 与 degen-guard 一致的行长上限：参与重复统计的行最多这么长。 */
const MAX_LINE_CHARS = 64;
/** 同一行种类上限，防脏数据撑爆内存。 */
const MAX_TRACKED_LINES = 20000;

/** 参与重复统计的行：去空白后 1..maxChars 个字符（口径与 dsh-degen-guard 相同）。 */
function isTrackableLine(line, maxChars) {
  const t = line.trim();
  return t.length > 0 && t.length <= maxChars;
}

/** 纯结构/符号行（```、}、---）不算碎念。口径与 dsh-degen-guard 相同。 */
function isStructuralLine(line) {
  const t = line.trim();
  if (t.length === 0) return true;
  return !/[\p{L}\p{N}]/u.test(t);
}

/** 按 SSE 帧切分（空行分隔，容忍 \r\n），返回 data 负载文本列表。 */
function frames(text) {
  const out = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    if (block.trim() === "") continue;
    const data = [];
    let event;
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      else if (line.startsWith("event:")) event = line.slice(6).trim();
    }
    if (data.length === 0) continue;
    out.push({ event, data: data.join("\n") });
  }
  return out;
}

/** 累积文本并按「同一非空行重复次数」统计，规则与 degen-guard 的判据完全一致。 */
function createLineCounter() {
  const counts = new Map();
  let tail = "";
  let maxRepeat = 0;
  let maxLine = "";
  function count(line) {
    if (!isTrackableLine(line, MAX_LINE_CHARS)) return;
    const key = line.trim();
    const seen = counts.get(key);
    if (seen === undefined) {
      if (counts.size >= MAX_TRACKED_LINES) return;
      counts.set(key, 1);
      if (maxRepeat < 1) maxRepeat = 1;
      return;
    }
    const next = seen + 1;
    counts.set(key, next);
    if (next > maxRepeat) {
      maxRepeat = next;
      maxLine = key;
    }
  }
  return {
    feed(text) {
      if (typeof text !== "string" || text === "") return;
      tail += text;
      const parts = tail.split("\n");
      tail = parts.pop() ?? "";
      for (const line of parts) count(line);
      if (tail.length > 8192) {
        count(tail);
        tail = "";
      }
    },
    result() {
      // 流结束时没有换行的最后一行也算一次（与守卫的实时判定口径略不同，
      // 这里更严格：它只用于离线统计，不影响任何中止决策）。
      if (tail !== "") count(tail);
      return { maxRepeat, maxLine, distinctLines: counts.size };
    },
  };
}

/**
 * 把一份原始 SSE 文本解析成事件与统计。
 *
 * @param {string} text - 上游原始 SSE 文本（已解码）。
 * @returns {{
 *   frames: number,
 *   types: Record<string, number>,
 *   malformedFrames: number,
 *   messageId: string,
 *   model: string,
 *   stopReason: string,
 *   reasoningChars: number,
 *   textChars: number,
 *   thinkingDeltas: number,
 *   textDeltas: number,
 *   toolDeltas: number,
 *   toolBlocks: number,
 *   maxRepeat: number,
 *   maxRepeatLine: string,
 *   distinctReasoningLines: number,
 *   hasStructuralTopLine: boolean,
 * }}
 */
export function analyzeSse(text) {
  const list = frames(text);
  const types = {};
  const reasoning = createLineCounter();
  const allText = createLineCounter();
  let malformedFrames = 0;
  let messageId = "";
  let model = "";
  let stopReason = "";
  let reasoningChars = 0;
  let textChars = 0;
  let thinkingDeltas = 0;
  let textDeltas = 0;
  let toolDeltas = 0;
  let toolBlocks = 0;

  const bump = (key) => {
    types[key] = (types[key] ?? 0) + 1;
  };

  for (const frame of list) {
    let value;
    try {
      value = JSON.parse(frame.data);
    } catch {
      malformedFrames += 1;
      bump("[malformed]");
      continue;
    }
    if (value === null || typeof value !== "object") {
      malformedFrames += 1;
      bump("[malformed]");
      continue;
    }

    // ── Anthropic Messages ──────────────────────────────────────────
    if (typeof value.type === "string" && !Array.isArray(value.choices)) {
      bump(value.type);
      if (value.type === "message_start" && value.message !== null && typeof value.message === "object") {
        if (typeof value.message.id === "string") messageId = value.message.id;
        if (typeof value.message.model === "string") model = value.message.model;
      }
      if (value.type === "content_block_start" && value.content_block !== null && typeof value.content_block === "object") {
        if (value.content_block.type === "tool_use") toolBlocks += 1;
      }
      if (value.type === "content_block_delta" && value.delta !== null && typeof value.delta === "object") {
        if (value.delta.type === "thinking_delta" && typeof value.delta.thinking === "string") {
          reasoningChars += value.delta.thinking.length;
          thinkingDeltas += 1;
          reasoning.feed(value.delta.thinking);
          allText.feed(value.delta.thinking);
        } else if (value.delta.type === "text_delta" && typeof value.delta.text === "string") {
          textChars += value.delta.text.length;
          textDeltas += 1;
          allText.feed(value.delta.text);
        } else if (value.delta.type === "input_json_delta" && typeof value.delta.partial_json === "string") {
          toolDeltas += 1;
        }
      }
      if (value.type === "message_delta" && value.delta !== null && typeof value.delta === "object") {
        if (typeof value.delta.stop_reason === "string") stopReason = value.delta.stop_reason;
      }
      continue;
    }

    // ── OpenAI Completions ──────────────────────────────────────────
    if (Array.isArray(value.choices)) {
      bump("completion-chunk");
      const choice = value.choices[0] ?? {};
      const delta = choice.delta ?? {};
      if (typeof delta.reasoning_content === "string" && delta.reasoning_content !== "") {
        reasoningChars += delta.reasoning_content.length;
        thinkingDeltas += 1;
        reasoning.feed(delta.reasoning_content);
        allText.feed(delta.reasoning_content);
      }
      if (typeof delta.content === "string" && delta.content !== "") {
        textChars += delta.content.length;
        textDeltas += 1;
        allText.feed(delta.content);
      }
      if (Array.isArray(delta.tool_calls)) {
        toolDeltas += delta.tool_calls.length;
        toolBlocks += delta.tool_calls.filter((call) => typeof call?.id === "string" && call.id !== "").length;
      }
      if (typeof choice.finish_reason === "string" && choice.finish_reason !== "") stopReason = choice.finish_reason;
      if (typeof value.model === "string" && value.model !== "") model = value.model;
      if (typeof value.id === "string" && messageId === "") messageId = value.id;
      continue;
    }

    bump(frame.event ?? "[untyped]");
  }

  const rep = reasoning.result();
  const all = allText.result();
  return {
    frames: list.length,
    types,
    malformedFrames,
    messageId,
    model,
    stopReason,
    reasoningChars,
    textChars,
    thinkingDeltas,
    textDeltas,
    toolDeltas,
    toolBlocks,
    maxRepeat: Math.max(rep.maxRepeat, all.maxRepeat),
    maxRepeatLine: rep.maxRepeat >= all.maxRepeat ? rep.maxLine : all.maxLine,
    distinctReasoningLines: rep.distinctLines,
    hasStructuralTopLine: isStructuralLine(rep.maxRepeat >= all.maxRepeat ? rep.maxLine : all.maxLine),
  };
}
