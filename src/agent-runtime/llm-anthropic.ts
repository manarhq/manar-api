import { randomUUID } from 'node:crypto';
import { BadRequestException, HttpException } from '@nestjs/common';
import { z } from 'zod';
import { applyDlpFloor } from '../common/dlp/dlp-classification';
import { denied } from './agent-task-access.service';
import type {
  UpstreamChatRequest,
  UpstreamChatResponse,
} from './llm-upstream.client';

/**
 * Anthropic Messages format for `POST /agent/v1/llm/anthropic/v1/messages`: request policy,
 * opaque fields kept out of DLP, response DLP (whole message and streamed), SSE, and the
 * translation to and from the OpenAI-format upstream. Pure functions; `LlmAnthropicService`
 * does the I/O.
 */

type Json = Record<string, unknown>;

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

const Block = z.object({ type: z.string() }).passthrough();

/** Required fields are checked here; the allowed set of top-level fields is `requestRefusal`'s. */
export const AnthropicMessagesRequestSchema = z
  .object({
    model: z.string().min(1).max(256),
    max_tokens: z.number().int().positive(),
    messages: z
      .array(
        z
          .object({
            role: z.string().min(1),
            content: z.union([z.string(), z.array(Block)]),
          })
          .passthrough(),
      )
      .min(1),
    system: z.union([z.string(), z.array(Block)]).optional(),
    tools: z
      .array(
        z
          .object({ type: z.string().optional(), name: z.string().optional() })
          .passthrough(),
      )
      .optional(),
    stream: z.boolean().optional(),
  })
  .passthrough();
export type AnthropicMessagesRequest = z.infer<
  typeof AnthropicMessagesRequestSchema
>;

export interface AnthropicUsage {
  input_tokens?: number;
  output_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_read_input_tokens?: number;
}
const USAGE_KEYS = [
  'input_tokens',
  'output_tokens',
  'cache_creation_input_tokens',
  'cache_read_input_tokens',
] as const;

/** Every token the upstream reports, cached ones included. */
export function usageTokens(usage: AnthropicUsage): number {
  return USAGE_KEYS.reduce((sum, k) => sum + (usage[k] ?? 0), 0);
}

/**
 * Top-level request fields passed on to the upstream (all scanned by DLP). Any other field is
 * refused with Anthropic's own wording, so a client that knows how drops it and retries.
 * `mcp_servers` and `container` are absent on purpose: the provider would reach the network.
 */
const PASSED_FIELDS = new Set([
  'model',
  'max_tokens',
  'messages',
  'system',
  'stream',
  'tools',
  'tool_choice',
  'temperature',
  'top_p',
  'top_k',
  'stop_sequences',
  'metadata',
  'thinking',
  'output_config',
  'output_format',
  'context_management',
  'service_tier',
]);

/**
 * Tool types that run on the agent's side: custom tools, Anthropic-defined client tools, and
 * tool search over the request's own tools. Server tools (web search, web fetch, code
 * execution, MCP connector) let the provider reach the network outside the agent's egress policy.
 */
const CLIENT_TOOL_TYPE =
  /^(custom|(bash|text_editor|computer|memory)_\d{8}|tool_search_tool_(regex|bm25)(_\d{8})?)$/;

const invalid = (message: string, reason: string) =>
  new BadRequestException({
    type: 'error',
    error: { type: 'invalid_request_error', message },
    reason,
  });

/**
 * Refusals decided by the request's shape (run after the task access check): a top-level field
 * outside `PASSED_FIELDS` (400 `llm_request_field_not_allowed`), a server tool (400 in the
 * wording Claude Code recognises, so it retries without that tool), or content DLP cannot read
 * (images, PDFs, file references: 403 `dlp_unscannable_content`).
 */
export function requestRefusal(
  request: AnthropicMessagesRequest,
): HttpException | null {
  const extra = Object.keys(request).find((k) => !PASSED_FIELDS.has(k));
  if (extra !== undefined) {
    return invalid(
      `${extra.slice(0, 64)}: Extra inputs are not permitted`,
      'llm_request_field_not_allowed',
    );
  }
  for (const [i, tool] of (request.tools ?? []).entries()) {
    if (tool.type !== undefined && !CLIENT_TOOL_TYPE.test(tool.type)) {
      return invalid(
        `tools.${i}: Input tag '${tool.type.slice(0, 64)}' is not allowed by Manar: server tools reach the network outside the agent's egress policy`,
        'llm_server_tool_not_allowed',
      );
    }
  }
  const content = [request.system, ...request.messages.map((m) => m.content)];
  if (content.some(unscannable)) return denied('dlp_unscannable_content');
  return null;
}

const VERSION = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The client headers the upstream gets: `anthropic-version` as a date (else 400), and only the
 * `anthropic-beta` values in `allowed` (others are dropped; a body field that needed one is then
 * refused by the upstream, and Claude Code retries without it).
 */
export function clientHeaders(
  raw: { version?: string; beta?: string },
  allowed: ReadonlySet<string>,
): { version?: string; beta?: string } {
  if (raw.version !== undefined && !VERSION.test(raw.version)) {
    throw invalid(
      'anthropic-version: expected a date such as 2023-06-01',
      'invalid_anthropic_version',
    );
  }
  const betas = [
    ...new Set(
      (raw.beta ?? '')
        .split(',')
        .map((b) => b.trim())
        .filter((b) => allowed.has(b)),
    ),
  ];
  return {
    ...(raw.version ? { version: raw.version } : {}),
    ...(betas.length ? { beta: betas.join(',') } : {}),
  };
}

/** Content blocks DLP cannot read: base64, URL or file sources, and file uploads. */
function unscannable(blocks: unknown): boolean {
  if (!Array.isArray(blocks)) return false;
  return blocks.some((b: Json) => {
    if (b?.type === 'tool_result') return unscannable(b.content);
    if (b?.type === 'container_upload') return true;
    if (b?.type !== 'image' && b?.type !== 'document') return false;
    const source = (b.source ?? {}) as Json;
    if (source.type === 'text') return false;
    if (source.type === 'content') return unscannable(source.content);
    return true;
  });
}

/** A path to a value inside a JSON document. */
type Slot = (string | number)[];

/** What a thinking signature or redacted-thinking payload looks like: base64, bounded. */
function opaqueValue(v: unknown): v is string {
  return (
    typeof v === 'string' &&
    v.length > 0 &&
    v.length <= 65_536 &&
    /^[A-Za-z0-9+/=_-]+$/.test(v)
  );
}

/** `signature` of a thinking block and `data` of a redacted-thinking block, when well formed. */
function blockSlot(block: unknown): string | undefined {
  const b = (block ?? {}) as Json;
  const key =
    b.type === 'thinking'
      ? 'signature'
      : b.type === 'redacted_thinking'
        ? 'data'
        : undefined;
  return key && opaqueValue(b[key]) ? key : undefined;
}

function directSlots(blocks: unknown, base: Slot): Slot[] {
  if (!Array.isArray(blocks)) return [];
  return blocks.flatMap((b, i) => {
    const key = blockSlot(b);
    return key ? [[...base, i, key]] : [];
  });
}

/** Request: only blocks directly in an assistant message's `content`. */
export const requestSlots = (prompt: { messages?: unknown }): Slot[] =>
  ((prompt.messages ?? []) as Json[]).flatMap((m, i) =>
    m?.role === 'assistant'
      ? directSlots(m.content, ['messages', i, 'content'])
      : [],
  );

/** Response: only blocks directly in `content`. */
export const contentSlots = (content: unknown): Slot[] =>
  directSlots(content, []);

/** Stream: a thinking block's start, and a `signature_delta`. */
export function eventSlots(data: Json): Slot[] {
  if (data.type === 'content_block_start') {
    const key = blockSlot(data.content_block);
    return key ? [['content_block', key]] : [];
  }
  const d = (data.delta ?? {}) as Json;
  return data.type === 'content_block_delta' &&
    d.type === 'signature_delta' &&
    opaqueValue(d.signature)
    ? [['delta', 'signature']]
    : [];
}

const at = (root: unknown, path: Slot): Json =>
  path.slice(0, -1).reduce((n: unknown, k) => (n as Json)[k], root) as Json;

/**
 * A copy of `value` with the model-signed fields `slots` finds (thinking signatures, redacted
 * thinking) emptied for DLP; `restore` puts them back into the scanned copy by path. They are
 * not text the model reads and must reach the upstream unchanged. Anything else, including a
 * thinking-shaped object nested in a tool input or result, is scanned.
 */
export function holdOpaque<T>(
  value: T,
  slots: (v: T) => Slot[],
): { held: T; restore: (scanned: T) => T } {
  const held = structuredClone(value);
  const paths = slots(held);
  const saved = paths.map((p) => at(held, p)[p.at(-1)!]);
  paths.forEach((p) => (at(held, p)[p.at(-1)!] = ''));
  return {
    held,
    restore: (scanned) => {
      paths.forEach((p, i) => (at(scanned, p)[p.at(-1)!] = saved[i]));
      return scanned;
    },
  };
}

export interface ScannedMessage {
  message: Json;
  credentialTypes: string[];
  piiTypes: string[];
}

/** Response DLP on a whole message: the deterministic floor (credentials block, UAE PII redacted). */
export function scanMessage(message: Json): ScannedMessage {
  const { held, restore } = holdOpaque(message.content, contentSlots);
  const floor = applyDlpFloor(held);
  return {
    message: { ...message, content: restore(floor.value) },
    credentialTypes: floor.credentialTypes,
    piiTypes: floor.piiTypes,
  };
}

/** Model output carried a credential: the call is cut (`dlp_policy_violation`). */
export class DlpBlocked extends Error {
  constructor(readonly types: string[]) {
    super('dlp_policy_violation');
    this.name = 'DlpBlocked';
  }
}

export interface SseEvent {
  event: string;
  data: Json;
}

export const sse = (e: SseEvent): string =>
  `event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`;

export const PING: SseEvent = { event: 'ping', data: { type: 'ping' } };

/** One SSE event (`event:` and `data:` lines); null for a comment-only chunk. Throws on bad JSON. */
export function parseSse(raw: string): SseEvent | null {
  let event = 'message';
  const data: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:'))
      data.push(line.slice(5).replace(/^ /, ''));
  }
  return data.length
    ? { event, data: JSON.parse(data.join('\n')) as Json }
    : null;
}

const ERROR_TYPES: Record<number, string> = {
  400: 'invalid_request_error',
  401: 'authentication_error',
  403: 'permission_error',
  404: 'not_found_error',
  413: 'request_too_large',
  429: 'rate_limit_error',
};

/**
 * A refusal as an Anthropic error body, keeping Manar's `decision`, `reason` and `dependency`
 * next to it (the stop codes clients act on). Non-HTTP errors are rethrown.
 */
export function anthropicError(error: unknown): { status: number; body: Json } {
  if (!(error instanceof HttpException)) throw error;
  const status = error.getStatus();
  const response = error.getResponse();
  const b = (
    typeof response === 'string' ? { message: response } : response
  ) as Json;
  if (b.type === 'error') return { status, body: b };
  const reason = typeof b.reason === 'string' ? b.reason : undefined;
  const message =
    reason ??
    (Array.isArray(b.message)
      ? b.message.join('; ')
      : str(b.message) || 'error');
  return {
    status,
    body: {
      type: 'error',
      error: {
        type:
          ERROR_TYPES[status] ??
          (status >= 500 ? 'api_error' : 'invalid_request_error'),
        message,
      },
      ...(b.decision ? { decision: b.decision } : {}),
      ...(reason ? { reason } : {}),
      ...(b.dependency ? { dependency: b.dependency } : {}),
    },
  };
}

export const errorEvent = (error: HttpException): SseEvent => ({
  event: 'error',
  data: anthropicError(error).body,
});

/**
 * Streamed text is always this far behind what the upstream sent: room for the plain-text part
 * of a credential pattern (a PEM header, `"client_secret": "`, `AccountKey=`, `Bearer `) to
 * complete before any of the secret after it is released.
 */
const CREDENTIAL_LOOKAHEAD = 512;
/** Characters of token-like secrets (JWT, bearer and SAS values, Entra client secrets). */
const TOKEN_CHAR = /[A-Za-z0-9_~.+/=%-]/;
/** A token-like run is held whole until it ends; one longer than this is treated as data. */
const TOKEN_RUN_MAX = 65_536;
/** Characters a UAE PII match can contain (digits, separators, the `AE` of an IBAN). */
const PII_CHAR = /[0-9AaEe +-]/;
/** A run of PII characters longer than this is not a single PII value; it is released. */
const PII_RUN_MAX = 512;

/** How much of `pending` can go out: nothing a credential or PII match could still grow into. */
function safeCut(pending: string): number {
  const end = pending.length;
  let pii = end;
  while (pii > 0 && PII_CHAR.test(pending[pii - 1]!)) pii--;
  if (end - pii > PII_RUN_MAX) pii = end;
  let token = end;
  while (token > 0 && TOKEN_CHAR.test(pending[token - 1]!)) token--;
  if (end - token > TOKEN_RUN_MAX) token = end;
  return Math.max(0, Math.min(pii, token, end - CREDENTIAL_LOOKAHEAD));
}

type Queued =
  | { kind: 'event'; event: SseEvent }
  | { kind: 'text'; index: number; field: 'text' | 'thinking'; text: string };

/**
 * Response DLP over a streamed message. Events leave in order through one message-level queue:
 * text and thinking deltas are held as long as a credential or PII match could still be growing
 * (`safeCut`), and every check reads the queued text of all blocks plus the tail already sent,
 * so a secret split across deltas or blocks is caught before any of it goes out. A tool call's
 * input is held whole until its block ends. A credential throws `DlpBlocked`. `message_delta` and
 * `message_stop` are kept in `held` for the caller to release after the call is charged and
 * audited.
 */
export class AnthropicStreamGuard {
  readonly usage: AnthropicUsage = {};
  readonly piiTypes = new Set<string>();
  readonly held: SseEvent[] = [];
  outputChars = 0;
  private readonly toolInput = new Map<number, string>();
  private readonly queue: Queued[] = [];
  private sentTail = '';

  push(e: SseEvent): SseEvent[] {
    const d = e.data;
    switch (d.type) {
      case 'ping':
        return [e];
      case 'message_start':
        this.addUsage((d.message as Json | undefined)?.usage);
        break;
      case 'message_delta':
        this.addUsage(d.usage);
        this.held.push(this.scan(e));
        return [];
      case 'message_stop':
        this.held.push(e);
        return this.release(true);
      case 'content_block_start': {
        const type = (d.content_block as Json | undefined)?.type;
        if (type === 'tool_use' || type === 'server_tool_use')
          this.toolInput.set(d.index as number, '');
        break;
      }
      case 'content_block_delta': {
        const index = d.index as number;
        const delta = (d.delta ?? {}) as Json;
        if (delta.type === 'text_delta' || delta.type === 'thinking_delta') {
          const field = delta.type === 'text_delta' ? 'text' : 'thinking';
          this.queueText(index, field, str(delta[field]));
          this.check();
          return this.release(false);
        }
        const input = this.toolInput.get(index);
        if (input !== undefined && delta.type === 'input_json_delta') {
          const part = str(delta.partial_json);
          this.toolInput.set(index, input + part);
          this.outputChars += part.length;
          return [];
        }
        break;
      }
      case 'content_block_stop': {
        const index = d.index as number;
        const input = this.toolInput.get(index);
        this.toolInput.delete(index);
        if (input) {
          // The input JSON as one string: a redaction placeholder is JSON-safe inside a string.
          this.queue.push({
            kind: 'event',
            event: delta(index, {
              type: 'input_json_delta',
              partial_json: this.redact(input),
            }),
          });
        }
        this.queue.push({ kind: 'event', event: e });
        return this.release(false);
      }
    }
    this.queue.push({ kind: 'event', event: this.scan(e) });
    return this.release(false);
  }

  private queueText(index: number, field: 'text' | 'thinking', text: string) {
    if (!text) return;
    this.outputChars += text.length;
    const last = this.queue.at(-1);
    if (last?.kind === 'text' && last.index === index && last.field === field)
      last.text += text;
    else this.queue.push({ kind: 'text', index, field, text });
  }

  private pendingText(): string {
    return this.queue.map((q) => (q.kind === 'text' ? q.text : '')).join('');
  }

  /** Credential shapes in what was last sent plus everything held, across blocks. */
  private check(): void {
    const found = applyDlpFloor(
      this.sentTail + this.pendingText(),
    ).credentialTypes;
    if (found.length) throw new DlpBlocked(found);
  }

  private release(final: boolean): SseEvent[] {
    if (final) this.check();
    const pending = this.pendingText();
    let cut = final ? pending.length : safeCut(pending);
    const out: SseEvent[] = [];
    while (this.queue.length) {
      const q = this.queue[0]!;
      if (q.kind === 'event') {
        out.push(q.event);
        this.queue.shift();
        continue;
      }
      if (cut <= 0) break;
      const part = q.text.slice(0, cut);
      cut -= part.length;
      q.text = q.text.slice(part.length);
      if (!q.text) this.queue.shift();
      this.sentTail = (this.sentTail + part).slice(-CREDENTIAL_LOOKAHEAD);
      out.push(
        delta(q.index, {
          type: `${q.field}_delta`,
          [q.field]: this.redact(part),
        }),
      );
      if (q.text) break;
    }
    return out;
  }

  private redact(text: string): string {
    const floor = applyDlpFloor(text);
    if (floor.credentialTypes.length)
      throw new DlpBlocked(floor.credentialTypes);
    floor.piiTypes.forEach((t) => this.piiTypes.add(t));
    return floor.value;
  }

  private scan(e: SseEvent): SseEvent {
    const { held, restore } = holdOpaque(e.data, eventSlots);
    const floor = applyDlpFloor(held);
    if (floor.credentialTypes.length)
      throw new DlpBlocked(floor.credentialTypes);
    floor.piiTypes.forEach((t) => this.piiTypes.add(t));
    return { event: e.event, data: restore(floor.value) };
  }

  private addUsage(usage: unknown): void {
    if (usage === null || typeof usage !== 'object') return;
    for (const k of USAGE_KEYS) {
      const v = (usage as Json)[k];
      if (typeof v === 'number') this.usage[k] = v; // message_delta usage is cumulative
    }
  }
}

const delta = (index: number, d: Json): SseEvent => ({
  event: 'content_block_delta',
  data: { type: 'content_block_delta', index, delta: d },
});

/** A whole message as the event sequence a streaming upstream would have sent. */
export function messageEvents(message: Json): SseEvent[] {
  const usage = (message.usage ?? {}) as AnthropicUsage;
  const events: SseEvent[] = [
    {
      event: 'message_start',
      data: {
        type: 'message_start',
        message: {
          ...message,
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { ...usage, output_tokens: 0 },
        },
      },
    },
  ];
  (message.content as Json[]).forEach((block, index) => {
    const start = (content_block: Json): SseEvent => ({
      event: 'content_block_start',
      data: { type: 'content_block_start', index, content_block },
    });
    if (block.type === 'text') {
      events.push(start({ type: 'text', text: '' }));
      events.push(delta(index, { type: 'text_delta', text: block.text }));
    } else if (block.type === 'tool_use') {
      events.push(start({ ...block, input: {} }));
      events.push(
        delta(index, {
          type: 'input_json_delta',
          partial_json: JSON.stringify(block.input ?? {}),
        }),
      );
    } else {
      events.push(start(block));
    }
    events.push({
      event: 'content_block_stop',
      data: { type: 'content_block_stop', index },
    });
  });
  events.push(
    {
      event: 'message_delta',
      data: {
        type: 'message_delta',
        delta: {
          stop_reason: message.stop_reason,
          stop_sequence: message.stop_sequence ?? null,
        },
        usage: { output_tokens: usage.output_tokens ?? 0 },
      },
    },
    { event: 'message_stop', data: { type: 'message_stop' } },
  );
  return events;
}

/** The text of a string or of the `text` blocks in a block list. */
function textOf(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((b: Json) => b?.type === 'text' && typeof b.text === 'string')
    .map((b: Json) => b.text as string)
    .join('\n');
}

/**
 * Anthropic request -> OpenAI chat completion request: system and mid-conversation system
 * entries, text, tool calls and tool results, custom tools and tool choice. Thinking blocks are
 * dropped (the OpenAI format has no place for them).
 */
export function toOpenAiChat(
  request: AnthropicMessagesRequest,
): UpstreamChatRequest {
  const messages: Json[] = [];
  if (request.system)
    messages.push({ role: 'system', content: textOf(request.system) });
  for (const m of request.messages) {
    const blocks: Json[] =
      typeof m.content === 'string'
        ? [{ type: 'text', text: m.content }]
        : m.content;
    if (m.role === 'assistant') {
      const toolCalls = blocks
        .filter((b) => b.type === 'tool_use')
        .map((b) => ({
          id: b.id,
          type: 'function',
          function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) },
        }));
      const text = textOf(blocks);
      messages.push({
        role: 'assistant',
        content: text || (toolCalls.length ? null : ''),
        ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
      });
      continue;
    }
    for (const b of blocks.filter((b) => b.type === 'tool_result')) {
      messages.push({
        role: 'tool',
        tool_call_id: b.tool_use_id,
        content: textOf(b.content) || (b.is_error ? 'error' : ''),
      });
    }
    const text = textOf(blocks);
    if (text)
      messages.push({
        role: m.role === 'system' ? 'system' : 'user',
        content: text,
      });
  }

  const tools = request.tools?.map((t, i) => {
    if (!t.input_schema) {
      throw new BadRequestException(
        `tools.${i}: only custom tools with an input_schema can be sent to this install's model`,
      );
    }
    return {
      type: 'function',
      function: {
        name: t.name,
        ...(t.description ? { description: t.description } : {}),
        parameters: t.input_schema,
      },
    };
  });
  const choice = request.tool_choice as Json | undefined;
  const toolChoice =
    choice?.type === 'any'
      ? 'required'
      : choice?.type === 'none'
        ? 'none'
        : choice?.type === 'tool'
          ? { type: 'function', function: { name: choice.name } }
          : choice?.type === 'auto'
            ? 'auto'
            : undefined;
  const temperature = request.temperature;
  return {
    messages,
    ...(tools?.length ? { tools } : {}),
    ...(toolChoice !== undefined ? { tool_choice: toolChoice } : {}),
    max_tokens: request.max_tokens,
    ...(typeof temperature === 'number' ? { temperature } : {}),
  };
}

const STOP_REASONS: Record<string, string> = {
  stop: 'end_turn',
  length: 'max_tokens',
  tool_calls: 'tool_use',
};

/** OpenAI chat completion -> Anthropic message (text, tool calls as `tool_use`, usage). */
export function fromOpenAiChat(
  body: UpstreamChatResponse['body'],
  model: string,
): Json {
  const choice = (body.choices as Json[] | undefined)?.[0] ?? {};
  const message = (choice.message ?? {}) as Json;
  const content: Json[] = [];
  if (typeof message.content === 'string' && message.content) {
    content.push({ type: 'text', text: message.content });
  }
  for (const call of (message.tool_calls as Json[] | undefined) ?? []) {
    const fn = (call.function ?? {}) as Json;
    let input: unknown = {};
    try {
      input = JSON.parse((fn.arguments as string) || '{}');
    } catch {
      // A model that writes broken JSON gets an empty input; the tool's own validation answers it.
    }
    content.push({
      type: 'tool_use',
      id: call.id ?? `toolu_${randomUUID()}`,
      name: fn.name,
      input,
    });
  }
  const hasTools = content.some((b) => b.type === 'tool_use');
  return {
    id: `msg_${str(body.id) || randomUUID()}`,
    type: 'message',
    role: 'assistant',
    model,
    content,
    stop_reason:
      STOP_REASONS[choice.finish_reason as string] ??
      (hasTools ? 'tool_use' : 'end_turn'),
    stop_sequence: null,
    usage: {
      input_tokens: body.usage?.prompt_tokens ?? 0,
      output_tokens: body.usage?.completion_tokens ?? 0,
    },
  };
}
