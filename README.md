# dsh-llm-wiretap

只读的**上游原始流记录器**，用来回答一个问题：推理退化循环里的重复，是模型/服务端吐出来的，还是 DSH 自己处理出来的？

配套 `dsh-degen-guard`（负责判定与止损）使用：守卫只能证明「退化发生在工具调用之前」，证明不了「重复来自上游还是本地」。两者的分界线是适配器收到的那串原始 SSE 字节，本插件就是把它原样留下来。

## 它记录什么

`globalThis.fetch` 上包一层，只拦截 **POST + `accept: text/event-stream` + JSON body** 的 `/messages` 与 `/chat/completions` 请求，其余请求原样放行。每个被捕获的请求落一个目录：

```
%DSH_HOME%\logs\wiretap\<yyyyMMddTHHmmss.mmm-NNN>\
  request.json    适配器实际发出的 body 原文（采样参数从这里读：model/max_tokens/thinking/output_config/max_tokens/temperature）
  response.sse    上游原始 SSE 文本，无损
  meta.json       元数据 + 解析统计（见下）
  pinned          maxRepeat >= pinRepeat 时才有的标记，表示这份不参与轮转删除
```

`meta.json` 里除了时间戳/状态码/响应头，还有 `sse` 统计：

| 字段 | 含义 |
| --- | --- |
| `frames` / `types` | SSE 帧数、各事件类型计数 |
| `reasoningChars` / `textChars` | 原始流里 reasoning 与正文的字符数 |
| `thinkingDeltas` / `textDeltas` / `toolBlocks` | 增量数、工具调用块数 |
| `maxRepeat` / `maxRepeatLine` | **同一非空行出现的最高次数**（与 dsh-degen-guard 判据同一口径，行长 ≤64） |
| `hasStructuralTopLine` | 重复最多的行是否只是 ` ``` ` / `}` 这类结构行 |
| `stopReason` / `model` / `messageId` | 终止原因、模型标识、上游消息 id |

请求头里的凭据（`authorization` / `x-api-key` / `x-dsh-auth-token` / `cookie`）**只记录 `<redacted len=N>`，值绝不入盘**。

## 怎么用它做实验

三层对齐（这是「重复产生在哪一层」的判据）：

1. **原始流**：`logs/wiretap/<id>/response.sse`
2. **适配器输出**：同一时刻的 `%DSH_HOME%\sessions\<工作区>\session-<id>\session.v<N>.jsonl.zstd` 里的 reasoning 块
3. **会话日志最终拼接**：上面同一个文件装配出的 assistant 消息

判定表：

| 原始流 | 会话日志 | 解释 |
| --- | --- | --- |
| 连续 100+ 次「做。」 | 同样重复 | 重复在上游生成或服务端解码，优先查模型/服务 |
| 正常 | 重复 | 优先查适配器、流式拼接、事件记录 |
| 重复后中断，`completed: false` | 继续重复 | 查 DSH 是否重复处理已收内容 |

`sessionId` 直接从请求头 `x-deepseek-harness-session-id` 取，和会话日志文件名对得上。

## 路由

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/dsh-llm-wiretap/recent?limit=N` | 最近 N 个捕获目录（含 meta） |
| GET | `/dsh-llm-wiretap/stats` | 本进程计数与最近 IO 错误 |
| POST | `/dsh-llm-wiretap/clear` | 清空捕获目录 |

## 配置

写在 `lib/index.js` 的 `DEFAULT_CONFIG`，可在 profile 的 `cordis.patch.yml` 按 id `llm-wiretap` 覆盖：

```yaml
- id: llm-wiretap
  config:
    enabled: true
    keep: 50              # 保留多少个未钉住的请求目录
    maxBytes: 16777216    # 单请求原始流上限，超出丢弃并标记 truncated
    pinRepeat: 100        # 原始流同句重复达到这个次数就钉住该请求
```

## 已知限制

- 记录的是 **fetch 解码后**的字节（`content-encoding` 已由 undici 解开），不是 TCP 层裸包。对「重复在哪一层」的判定没有影响。
- Electron/undici 之外的 fetch 实现（`dsh-http-proxy` 若替换了 `globalThis.fetch`）会被本插件包在外层，仍然生效；如果它在本插件之后才包装，就会绕过本插件，此时 `stats.tapped` 不增长，用 `/stats` 能看出来。
- `response.clone()` 会额外占用一份内存直到旁路读完；`maxBytes` 上限保证不会无限增长。
- 只有 reasoning、没有正文或工具调用的完整响应会自动写入 `pinned`，不受 `keep` 轮转影响。
