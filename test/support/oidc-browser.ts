import { createHash, randomBytes } from 'node:crypto';

/**
 * A minimal browser for Keycloak's authorization code flow (PKCE S256): it
 * keeps cookies, follows redirects by hand, fills the login form (of the
 * realm, or of an upstream identity provider after `kc_idp_hint`) and the
 * consent form, and stops at the client's redirect URI with the code. Lets
 * the e2e suite get tokens the way Copilot Studio and ChatGPT do, with no
 * password grant anywhere.
 */
export interface Login {
  username: string;
  password: string;
}

export type FlowResult =
  { code: string; verifier: string } | { page: string; status: number };

function decodeHtml(value: string): string {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

function formOf(
  html: string,
): { action: string; fields: Record<string, string> } | null {
  const form = /<form[^>]*action="([^"]+)"[^>]*>([\s\S]*?)<\/form>/i.exec(html);
  if (!form) return null;
  const fields: Record<string, string> = {};
  for (const input of form[2]!.matchAll(/<input[^>]*>/gi)) {
    const name = /name="([^"]+)"/.exec(input[0])?.[1];
    const type = /type="([^"]+)"/.exec(input[0])?.[1] ?? 'text';
    const value = /value="([^"]*)"/.exec(input[0])?.[1] ?? '';
    if (name && type === 'hidden') fields[name] = decodeHtml(value);
  }
  return { action: decodeHtml(form[1]!), fields };
}

export async function authorizationCode(input: {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  /** Logins to answer forms with, in order (realm form, or upstream provider form). */
  logins: Login[];
  idpHint?: string;
}): Promise<FlowResult> {
  // name + path -> value: two realms on one host set cookies of the same name on their own paths.
  const cookies = new Map<
    string,
    { name: string; path: string; value: string }
  >();
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const logins = [...input.logins];

  const request = async (url: string, form?: Record<string, string>) => {
    const target = new URL(url);
    const response = await fetch(url, {
      method: form ? 'POST' : 'GET',
      redirect: 'manual',
      headers: {
        cookie: [...cookies.values()]
          .filter((c) => target.pathname.startsWith(c.path))
          .map((c) => `${c.name}=${c.value}`)
          .join('; '),
        ...(form
          ? { 'Content-Type': 'application/x-www-form-urlencoded' }
          : {}),
      },
      body: form ? new URLSearchParams(form) : undefined,
    });
    for (const header of response.headers.getSetCookie()) {
      const [pair, ...attributes] = header.split(';');
      const eq = pair!.indexOf('=');
      const name = pair!.slice(0, eq).trim();
      const path =
        attributes
          .map((a) => a.trim())
          .find((a) => a.toLowerCase().startsWith('path='))
          ?.slice(5) ?? '/';
      cookies.set(`${name}|${path}`, {
        name,
        path,
        value: pair!.slice(eq + 1),
      });
    }
    return response;
  };

  let url = `${input.issuer}/protocol/openid-connect/auth?${new URLSearchParams(
    {
      client_id: input.clientId,
      redirect_uri: input.redirectUri,
      response_type: 'code',
      scope: input.scope,
      state: randomBytes(8).toString('hex'),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...(input.idpHint ? { kc_idp_hint: input.idpHint } : {}),
    },
  ).toString()}`;
  let form: Record<string, string> | undefined;
  for (let hop = 0; hop < 20; hop += 1) {
    const response = await request(url, form);
    form = undefined;
    const location = response.headers.get('location');
    if (location) {
      const next = new URL(location, url).toString();
      if (next.startsWith(input.redirectUri)) {
        const code = new URL(next).searchParams.get('code');
        if (!code) return { page: next, status: response.status };
        return { code, verifier };
      }
      url = next;
      continue;
    }
    const html = await response.text();
    const page = formOf(html);
    if (page && /name="password"/.test(html) && logins.length) {
      const login = logins.shift()!;
      url = new URL(page.action, url).toString();
      form = {
        ...page.fields,
        username: login.username,
        password: login.password,
      };
      continue;
    }
    if (page && /name="accept"/.test(html)) {
      url = new URL(page.action, url).toString();
      form = { ...page.fields, accept: 'Yes' };
      continue;
    }
    return { page: html, status: response.status };
  }
  throw new Error('Too many redirects in the authorization code flow');
}

/** Exchanges a code (client_secret_basic, PKCE). */
export async function exchangeCode(input: {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  verifier: string;
}): Promise<string> {
  const response = await fetch(
    `${input.issuer}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(
          `${encodeURIComponent(input.clientId)}:${encodeURIComponent(input.clientSecret)}`,
        ).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.code,
        redirect_uri: input.redirectUri,
        code_verifier: input.verifier,
      }),
    },
  );
  const body = (await response.json()) as Record<string, string>;
  if (!response.ok || !body.access_token) {
    throw new Error(
      `Code exchange failed: HTTP ${response.status} ${body.error ?? ''}`,
    );
  }
  return body.access_token;
}

/** A short description of a Keycloak page for failure messages (title, alert, form target). */
export function describePage(html: string): string {
  const text = (re: RegExp) =>
    re.exec(html)?.[1]?.replace(/\s+/g, ' ').trim() ?? '';
  return [
    text(/<title>([\s\S]*?)<\/title>/i),
    text(/kc-feedback-text">([\s\S]*?)</i) ||
      text(/class="[^"]*alert[^"]*"[^>]*>([\s\S]*?)<\/div>/i),
    text(/<form[^>]*action="([^"?]+)/i),
    text(/id="input-error[^"]*"[^>]*>([\s\S]*?)</i),
  ]
    .filter(Boolean)
    .join(' | ');
}
