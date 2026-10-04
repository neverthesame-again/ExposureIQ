// Gemini client (REST generateContent with function calling) and the agent loop that the four
// agents run on. The model plans and decides; tools are plain functions in our backend; guardrails
// stay in our code, outside the model.
//
// Quotas are per model (the free tier allows ~5 requests/min on the larger Flash models), so the
// client keeps a per-minute budget for each model, pauses a model when Google answers 429, and
// starts each agent run on whichever configured model has capacity. A run stays on one model.
import { config } from '../config.js';
import { fetchJson } from '../connectors/http.js';

const MODELS = [...new Set([config.gemini.model, ...config.gemini.fallbackModels])];

export const ai = {
  enabled: !!config.gemini.apiKey,
  model: config.gemini.model,
  models: MODELS,
  calls: 0,
  runs: 0,
  inputTokens: 0,
  outputTokens: 0,
  lastError: null,
  thoughts: true, // ask for thought summaries; switched off automatically if a model refuses
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

// ---------------- per-model quota ----------------
const quota = Object.fromEntries(MODELS.map((m) => [m, { calls: [], cooldownUntil: 0, note: null }]));

function capacity(m) {
  const q = quota[m];
  const now = Date.now();
  while (q.calls.length && now - q.calls[0] > 60000) q.calls.shift();
  if (q.cooldownUntil > now) return 0;
  return config.gemini.maxCallsPerMinute - q.calls.length;
}

// The model a run should use: the first (preferred) model with room, else the one that frees up soonest.
export function pickModel(exclude = new Set()) {
  const options = MODELS.filter((m) => !exclude.has(m));
  if (!options.length) return null;
  const best = [...options].sort((a, b) => capacity(b) - capacity(a))[0]; // most room left; ties keep the preferred order
  if (capacity(best) > 0) return best;
  return [...options].sort((a, b) => quota[a].cooldownUntil - quota[b].cooldownUntil)[0];
}

// Calls that can be sent right now across all models.
export const headroom = () => MODELS.reduce((n, m) => n + Math.max(0, capacity(m)), 0);

// Seconds until any model can take a call (0 = one can now).
export function coolingDownFor() {
  if (MODELS.some((m) => capacity(m) > 0)) return 0;
  const now = Date.now();
  const next = Math.min(...MODELS.map((m) => Math.max(quota[m].cooldownUntil, (quota[m].calls[0] || now) + 60000)));
  return Math.max(0, Math.ceil((next - now) / 1000));
}

export const quotaView = () => MODELS.map((m) => ({ model: m, usedThisMinute: quota[m].calls.length, limitPerMinute: config.gemini.maxCallsPerMinute, coolingDownSec: Math.max(0, Math.ceil((quota[m].cooldownUntil - Date.now()) / 1000)), note: quota[m].note }));

async function waitForSlot(m) {
  for (;;) {
    if (capacity(m) > 0) { quota[m].calls.push(Date.now()); return; }
    const q = quota[m];
    const w = Math.max(q.cooldownUntil - Date.now(), q.calls.length ? 60000 - (Date.now() - q.calls[0]) + 50 : 0);
    if (w > 45000) throw Object.assign(new Error(`${m} is out of quota for ${Math.ceil(w / 1000)}s`), { status: 429 });
    await sleep(Math.min(Math.max(w, 200), 5000));
  }
}

function readQuotaError(body) {
  try {
    const err = JSON.parse(body).error || {};
    const retry = err.details?.find((d) => /RetryInfo/.test(d['@type']))?.retryDelay;
    const v = err.details?.find((d) => /QuotaFailure/.test(d['@type']))?.violations?.[0] || {};
    return { day: /PerDay/i.test(`${v.quotaId} ${v.quotaMetric}`), limit: v.quotaValue || null, retryInSec: retry ? Math.ceil(parseFloat(retry)) : null };
  } catch {
    return { day: false, limit: null, retryInSec: null };
  }
}

async function generate(model, { system, contents, tools, mode = 'AUTO' }, attempt = 0) {
  await waitForSlot(model);
  const body = {
    systemInstruction: { parts: [{ text: system }] },
    contents,
    ...(tools?.length ? { tools: [{ functionDeclarations: tools }], toolConfig: { functionCallingConfig: { mode } } } : {}),
    generationConfig: { temperature: 0.2, ...(ai.thoughts ? { thinkingConfig: { includeThoughts: true } } : {}) },
  };
  let j;
  try {
    j = await fetchJson(`${config.gemini.apiBase}/models/${encodeURIComponent(model)}:generateContent`, {
      method: 'POST', headers: { 'x-goog-api-key': config.gemini.apiKey }, body, timeoutMs: 90000, retries: 0,
    });
  } catch (e) {
    const q = quota[model];
    if (ai.thoughts && e.status === 400 && /thinking|thought/i.test(e.body || '')) { ai.thoughts = false; return generate(model, { system, contents, tools, mode }, attempt); }
    if (e.status === 429) {
      const info = readQuotaError(e.body);
      const wait = info.day ? 3600 : info.retryInSec ?? 30;
      q.cooldownUntil = Date.now() + wait * 1000;
      q.note = info.day ? `daily quota used${info.limit ? ` (${info.limit}/day)` : ''}` : `rate limit${info.limit ? ` (${info.limit}/min)` : ''}`;
      ai.lastError = `${model}: ${q.note}; paused ${wait}s`;
      if (!info.day && wait <= 35 && attempt === 0) return generate(model, { system, contents, tools, mode }, 1);
    } else if (e.status === 503 || e.status >= 500 || e.status === 0) {
      q.cooldownUntil = Date.now() + 20000; // overloaded: give it a moment, other models take over
      q.note = 'overloaded';
      ai.lastError = `${model}: temporarily unavailable (HTTP ${e.status || 'network'})`;
      if (attempt === 0) { await sleep(3000); return generate(model, { system, contents, tools, mode }, 1); }
    } else {
      ai.lastError = `${model}: ${e.message}${e.body ? ` · ${e.body.slice(0, 200)}` : ''}`;
    }
    throw e;
  }
  ai.calls++;
  ai.inputTokens += j.usageMetadata?.promptTokenCount || 0;
  ai.outputTokens += j.usageMetadata?.candidatesTokenCount || 0;
  const cand = j.candidates?.[0];
  if (!cand?.content?.parts) {
    ai.lastError = `${model}: no content returned (${cand?.finishReason || j.promptFeedback?.blockReason || 'unknown reason'})`;
    throw new Error(ai.lastError);
  }
  quota[model].note = null;
  ai.lastError = null;
  return cand.content;
}

// Runs one agent to completion.
//   tools: { name: { description, parameters (Gemini schema), run(args) → object with an optional `summary` } }
//   finalTool: name of the tool that ends the run with a decision, or null for a free-text answer (copilot)
//   onModel(model): told which model the run uses, before the first call
// If a model is rate-limited or overloaded part-way, the run starts again on the next model
// (a conversation cannot move between models mid-way because of thought signatures).
export async function runAgent(opts) {
  const tried = new Set();
  const trace = opts.trace || [];
  for (;;) {
    const model = pickModel(tried);
    tried.add(model);
    opts.onModel?.(model);
    try {
      return await runOnModel(model, { ...opts, trace });
    } catch (e) {
      const transient = e.status === 429 || e.status === 0 || e.status >= 500;
      const next = pickModel(tried);
      if (!transient || !next) throw e;
      trace.push({ type: 'guardrail', text: `${model} is ${e.status === 429 ? 'rate-limited' : 'unavailable'} right now; starting again on ${next}.` });
    }
  }
}

async function runOnModel(model, { system, prompt, tools, finalTool, maxSteps = config.gemini.maxSteps, trace }) {
  const decls = Object.entries(tools).map(([name, t]) => ({ name, description: t.description, parameters: t.parameters }));
  const contents = [{ role: 'user', parts: [{ text: prompt }] }];
  ai.runs++;
  for (let step = 0; step < maxSteps; step++) {
    const last = step === maxSteps - 1;
    const content = await generate(model, { system, contents, tools: decls, mode: last && finalTool ? 'ANY' : 'AUTO' });
    contents.push(content); // echoed back as-is so thought signatures survive the next turn
    const parts = content.parts || [];
    const calls = parts.filter((p) => p.functionCall).map((p) => p.functionCall);
    for (const p of parts) {
      if (p.text?.trim() && (p.thought || calls.length || finalTool)) trace.push({ type: 'thought', text: clip(p.text.split('*').join('').split(/\s+/).join(' ').trim(), 420) });
    }

    if (!calls.length) {
      const answer = parts.filter((p) => p.text && !p.thought).map((p) => p.text).join('\n').trim();
      if (!finalTool) return { trace, answer, model, steps: step + 1 };
      contents.push({ role: 'user', parts: [{ text: `Now call ${finalTool} with your decision.` }] });
      continue;
    }

    const responses = [];
    for (const call of calls) {
      if (call.name === finalTool) return { trace, final: call.args || {}, model, steps: step + 1 };
      const tool = tools[call.name];
      let result;
      try {
        result = tool ? await tool.run(call.args || {}) : { error: `Unknown tool ${call.name}` };
      } catch (e) {
        result = { error: e.message };
      }
      trace.push({ type: 'tool', tool: call.name, args: call.args || {}, result: clip(result?.summary || result?.error || JSON.stringify(result), 260) });
      responses.push({ functionResponse: { ...(call.id ? { id: call.id } : {}), name: call.name, response: { result } } });
    }
    contents.push({ role: 'user', parts: responses });
  }
  throw new Error(`No decision within ${maxSteps} steps`);
}

// Run budgets. People come first: background work (the live feed) gets at most
// AGENT_BACKGROUND_RUNS_PER_MIN Gemini runs and only while enough capacity is left for a question;
// a person's request waits for capacity instead of falling back.
const recent = [];
const recentBackground = [];
let peopleWaiting = 0;
const prune = (arr) => { while (arr.length && Date.now() - arr[0] > 60000) arr.shift(); };
const RESERVE = 3; // calls kept free for a question (a copilot answer takes 2-3 calls)

export function tryAcquireBackgroundRun() {
  prune(recent); prune(recentBackground);
  if (peopleWaiting > 0 || headroom() < RESERVE + 2) return false;
  if (recentBackground.length >= config.gemini.backgroundRunsPerMinute || recent.length >= config.gemini.maxRunsPerMinute) return false;
  const now = Date.now();
  recent.push(now); recentBackground.push(now);
  return true;
}
export async function acquireInteractiveRun(maxWaitMs = 60000) {
  const until = Date.now() + maxWaitMs;
  peopleWaiting++;
  try {
    for (;;) {
      prune(recent);
      if (headroom() > 0) { recent.push(Date.now()); return true; }
      if (Date.now() > until) return false;
      await sleep(1000);
    }
  } finally { peopleWaiting--; }
}
export const runsThisMinute = () => { prune(recent); return recent.length; };
