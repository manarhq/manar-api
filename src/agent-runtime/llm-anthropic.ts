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

/**
 * Required fields are checked; every other field passes through unchanged (Claude Code adds
 * fields paired with `anthropic-beta` values, and stripping one breaks the pair).
 */
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
 * Tool types that run on the agent's side: custom tools, Anthropic-defined client tools, and
 * tool search over the request's own tools. Server tools (web search, web fetch, code
 * execution, MCP connector) let the provider reach the network outside the agent's egress policy.
 */
const CLIENT_TOOL_TYPE =
  /^(custom|(bash|text_editor|computer|memory)_\d{8}|tool_search_tool_(regex|bm25)(_\d{8})?)$/;

/**
 * Refusals decided by the request's shape, before any gate: a server tool or provider-side
 * connector (400 in the wording Claude Code recognises, so it retries without that tool), or
 * content DLP cannot read (images, PDFs, file references: 403 `dlp_unscannable_content`).
 */
export function requestRefusal(
  request: AnthropicMessagesRequest,
): HttpException | null {
  const notAllowed = (message: string) =>
    new BadRequestException({
      type: 'error',
      error: { type: 'invalid_request_error', message },
      reason: 'llm_server_tool_not_allowed',
    });
  for (const [i, tool] of (request.tools ?? []).entries()) {
    if (tool.type !== undefined && !CLIENT_TOOL_TYPE.test(tool.type)) {
      return notAllowed(
        `tools.${i}: Input tag '${tool.type.slice(0, 64)}' is not allowed by Manar: server tools reach the network outside the agent's egress policy`,
      );
    }
  }
  for (const field of ['mcp_servers', 'container']) {
    if (request[field] !== undefined) {
      return notAllowed(
        `${field}: not allowed by Manar: the provider would reach the network outside the agent's egress policy`,
      );
    }
  }
  const content = [request.system, ...request.messages.map((m) => m.content)];
  if (content.some(unscannable)) return denied('dlp_unscannable_content');
  return null;
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

/** Model-signed fields: not text the model reads, and they must reach the upstream unchanged. */
const OPAQUE: Record<string, string> = {
  thinking: 'signature',
  redacted_thinking: 'data',
  signature_delta: 'signature',
};

function eachOpaque(node: unknown, visit: (o: Json, key: string) => void) {
  if (Array.isArray(node)) node.forEach((n) => eachOpaque(n, visit));
  else if (node !== null && typeof node === 'object') {
    const o = node as Json;
    const key = OPAQUE[o.type as string];
    if (key && typeof o[key] === 'string') visit(o, key);
    Object.values(o).forEach((v) => eachOpaque(v, visit));
  }
}

/**
 * A copy of `value` with thinking signatures and redacted-thinking data emptied, for DLP;
 * `restore` puts them back into the scanned copy (same shape, same order).
 */
export function holdOpaque<T>(value: T): {
  held: T;
  restore: (scanned: T) => T;
} {
  const saved: string[] = [];
  const held = structuredClone(value);
  eachOpaque(held, (o, k) => {
    saved.push(o[k] as string);
    o[k] = '';
  });
  return {
    held,
    restore: (scanned) => {
      let i = 0;
      eachOpaque(scanned, (o, k) => {
        o[k] = saved[i++];
      });
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
  const { held, restore } = holdOpaque(message.content);
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

/** Credential shapes are looked for in this much of a block's latest text. */
const CREDENTIAL_WINDOW = 8192;
/**
 * Characters a UAE PII match can contain (digits, separators, the `AE` of an IBAN). Streamed
 * text is released up to the last character outside this set, so a match is never split
 * between what was sent and what is still held.
 */
const PII_CHAR = /[0-9AaEe +-]/;
/**
 * ponytail: a run of PII characters longer than this is released anyway (a match split there
 * goes out unredacted); hold per pattern if that ever matters.
 */
const HOLD_MAX = 512;

interface OpenBlock {
  json: boolean;
  field?: 'text' | 'thinking';
  pending: string;
  seen: string;
}

/**
 * Response DLP over a streamed message, event by event: text and thinking deltas are held back
 * only as far as a PII match could still be growing, then released redacted; a tool call's
 * input is held whole until its block ends and released in one `input_json_delta`; a credential
 * shape anywhere throws `DlpBlocked`. `message_delta` and `message_stop` are kept in `held` for
 * the caller to release after the call is charged and audited.
 *
 * ponytail: a credential is found once it is complete, so its first characters may already be
 * out in a text delta; hold text like tool input if that ever matters.
 */
export class AnthropicStreamGuard {
  readonly usage: AnthropicUsage = {};
  readonly piiTypes = new Set<string>();
  readonly held: SseEvent[] = [];
  outputChars = 0;
  private readonly blocks = new Map<number, OpenBlock>();

  push(e: SseEvent): SseEvent[] {
    const d = e.data;
    switch (d.type) {
      case 'ping':
        return [e];
      case 'message_start':
        this.addUsage((d.message as Json | undefined)?.usage);
        return [this.scan(e)];
      case 'message_delta':
        this.addUsage(d.usage);
        this.held.push(this.scan(e));
        return [];
      case 'message_stop':
        this.held.push(e);
        return [];
      case 'content_block_start': {
        const type = (d.content_block as Json | undefined)?.type;
        this.blocks.set(d.index as number, {
          json: type === 'tool_use' || type === 'server_tool_use',
          pending: '',
          seen: '',
        });
        return [this.scan(e)];
      }
      case 'content_block_delta': {
        const index = d.index as number;
        const delta = (d.delta ?? {}) as Json;
        const block = this.blocks.get(index);
        if (
          block &&
          (delta.type === 'text_delta' || delta.type === 'thinking_delta')
        ) {
          const field = delta.type === 'text_delta' ? 'text' : 'thinking';
          return this.text(index, block, field, str(delta[field]));
        }
        if (block?.json && delta.type === 'input_json_delta') {
          const part = str(delta.partial_json);
          block.pending += part;
          this.outputChars += part.length;
          return [];
        }
        return [this.scan(e)];
      }
      case 'content_block_stop': {
        const index = d.index as number;
        const out = this.flush(index);
        this.blocks.delete(index);
        return [...out, e];
      }
      default:
        return [this.scan(e)];
    }
  }

  private text(
    index: number,
    block: OpenBlock,
    field: 'text' | 'thinking',
    chunk: string,
  ): SseEvent[] {
    block.field = field;
    this.outputChars += chunk.length;
    block.seen = (block.seen + chunk).slice(-CREDENTIAL_WINDOW);
    const found = applyDlpFloor(block.seen).credentialTypes;
    if (found.length) throw new DlpBlocked(found);
    block.pending += chunk;
    let cut = block.pending.length;
    while (cut > 0 && PII_CHAR.test(block.pending[cut - 1]!)) cut--;
    if (block.pending.length - cut > HOLD_MAX) cut = block.pending.length;
    return this.release(index, block, cut);
  }

  private release(index: number, block: OpenBlock, cut: number): SseEvent[] {
    if (cut === 0) return [];
    const text = this.redact(block.pending.slice(0, cut));
    block.pending = block.pending.slice(cut);
    const field = block.field ?? 'text';
    return [delta(index, { type: `${field}_delta`, [field]: text })];
  }

  private flush(index: number): SseEvent[] {
    const block = this.blocks.get(index);
    if (!block?.pending) return [];
    if (!block.json) return this.release(index, block, block.pending.length);
    // The input JSON as one string: a redaction placeholder is JSON-safe inside a string.
    const json = this.redact(block.pending);
    block.pending = '';
    return [delta(index, { type: 'input_json_delta', partial_json: json })];
  }

  private redact(text: string): string {
    const floor = applyDlpFloor(text);
    if (floor.credentialTypes.length)
      throw new DlpBlocked(floor.credentialTypes);
    floor.piiTypes.forEach((t) => this.piiTypes.add(t));
    return floor.value;
  }

  private scan(e: SseEvent): SseEvent {
    const { held, restore } = holdOpaque(e.data);
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
