"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const crypto = require("node:crypto");

const handler = require("../../preview-site/api/v1/previews/github/[owner]/[repo]/[pull_request].js");
const providerEnv = {
  GREGORFORGE_PREVIEW_PROVIDER_TOKEN: "provider-token-0123456789abcdef012345",
  GREGORFORGE_PREVIEW_ATTESTATION_KEY: "0123456789abcdef0123456789abcdef",
  VERCEL_TOKEN: "vercel-read-token",
  VERCEL_PROJECT_ID: "prj_gregorforge",
  VERCEL_TEAM_ID: "team_gregorforge",
};

function fakeResponse() {
  return {
    headers: {},
    statusCode: 200,
    setHeader(name, value) {
      this.headers[name] = value;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
  };
}

function validDeployment(overrides = {}) {
  return {
    uid: "dpl_123abc",
    url: "gregorforge-git-test-aram07324.vercel.app",
    state: "READY",
    target: null,
    createdAt: Date.now(),
    meta: {
      githubPrId: "42",
      githubCommitSha: "a".repeat(40),
      githubCommitOrg: "aram07324",
      githubCommitRepo: "gregorforge",
    },
    ...overrides,
  };
}

async function invoke({ query, method = "GET", authorization = "Bearer provider-token" } = {}) {
  const response = fakeResponse();
  await handler(
    { method, query, headers: { authorization } },
    response,
  );
  return response;
}

test("attests only a ready Vercel deployment matching the repository and PR", async (t) => {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  Object.assign(process.env, providerEnv);
  global.fetch = async (url, options) => {
    const parsed = new URL(url);
    assert.equal(parsed.hostname, "api.vercel.com");
    assert.equal(parsed.pathname, "/v7/deployments");
    assert.equal(parsed.searchParams.get("projectId"), "prj_gregorforge");
    assert.equal(parsed.searchParams.get("state"), "READY");
    assert.equal(parsed.searchParams.get("sha"), "a".repeat(40));
    assert.equal(parsed.searchParams.get("teamId"), "team_gregorforge");
    assert.equal(options.headers.Authorization, "Bearer vercel-read-token");
    return {
      ok: true,
      json: async () => ({
        deployments: [
          validDeployment({ state: "BUILDING" }),
          validDeployment({ target: "production" }),
          validDeployment({ meta: { ...validDeployment().meta, githubPrId: "41" } }),
          validDeployment({ meta: { ...validDeployment().meta, githubCommitSha: "b".repeat(40) } }),
          validDeployment(),
        ],
      }),
    };
  };
  t.after(() => {
    global.fetch = originalFetch;
    for (const name of Object.keys(process.env)) {
      if (!(name in originalEnv)) delete process.env[name];
    }
    Object.assign(process.env, originalEnv);
  });

  const response = await invoke({
    query: { owner: "aram07324", repo: "gregorforge", pull_request: "42", head_sha: "a".repeat(40) },
    authorization: `Bearer ${providerEnv.GREGORFORGE_PREVIEW_PROVIDER_TOKEN}`,
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.origin, "https://gregorforge-git-test-aram07324.vercel.app");
  assert.equal(response.body.head_sha, "a".repeat(40));
  assert.equal(response.body.status, "ready");
  assert.match(response.body.signature, /^[a-f0-9]{64}$/);

  const unsigned = { ...response.body };
  delete unsigned.signature;
  const canonical = JSON.stringify(Object.fromEntries(
    Object.entries(unsigned).sort(([left], [right]) => left.localeCompare(right)),
  ));
  const expected = crypto.createHmac("sha256", providerEnv.GREGORFORGE_PREVIEW_ATTESTATION_KEY)
    .update(canonical, "ascii")
    .digest("hex");
  assert.equal(response.body.signature, expected);
  assert.equal(response.headers["Cache-Control"], "no-store");
});

test("rejects unauthorized callers before contacting Vercel", async (t) => {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  Object.assign(process.env, providerEnv);
  global.fetch = async () => assert.fail("must not query Vercel");
  t.after(() => {
    global.fetch = originalFetch;
    for (const name of Object.keys(process.env)) {
      if (!(name in originalEnv)) delete process.env[name];
    }
    Object.assign(process.env, originalEnv);
  });

  const response = await invoke({
    query: { owner: "aram07324", repo: "gregorforge", pull_request: "42", head_sha: "a".repeat(40) },
    authorization: "Bearer wrong-token",
  });
  assert.equal(response.statusCode, 401);
});

test("rejects wrong repos, malformed PR numbers, and unsupported methods", async () => {
  const wrongRepo = await invoke({
    query: {
      owner: "someone-else",
      repo: "project",
      pull_request: "42",
      head_sha: "a".repeat(40),
    },
  });
  assert.equal(wrongRepo.statusCode, 404);

  const malformed = await invoke({
    query: { owner: "aram07324", repo: "gregorforge", pull_request: "../42" },
  });
  assert.equal(malformed.statusCode, 400);

  const method = await invoke({
    method: "POST",
    query: { owner: "aram07324", repo: "gregorforge", pull_request: "42", head_sha: "a".repeat(40) },
  });
  assert.equal(method.statusCode, 405);
  assert.equal(method.headers.Allow, "GET");
});

test("never attests non-Vercel deployment hostnames", async (t) => {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };
  Object.assign(process.env, providerEnv);
  global.fetch = async () => ({
    ok: true,
    json: async () => ({
      deployments: [validDeployment({ url: "attacker.example", uid: "dpl_attack" })],
    }),
  });
  t.after(() => {
    global.fetch = originalFetch;
    for (const name of Object.keys(process.env)) {
      if (!(name in originalEnv)) delete process.env[name];
    }
    Object.assign(process.env, originalEnv);
  });

  const response = await invoke({
    query: {
      owner: "aram07324",
      repo: "gregorforge",
      pull_request: "42",
      head_sha: "a".repeat(40),
    },
    authorization: `Bearer ${providerEnv.GREGORFORGE_PREVIEW_PROVIDER_TOKEN}`,
  });
  assert.equal(response.statusCode, 404);
  assert.deepEqual(response.body, { error: "ready_preview_not_found" });
});
