"use strict";

const crypto = require("node:crypto");

const REPOSITORY = "aram07324/gregorforge";
const ATTESTATION_TTL_MS = 10 * 60 * 1000;
const SIGNED_FIELDS = [
  "expires_at",
  "head_sha",
  "origin",
  "preview_id",
  "pull_request",
  "repository",
  "status",
];

function respond(res, status, value) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.status(status).json(value);
}

function secureEqual(left, right) {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length
    && crypto.timingSafeEqual(leftBytes, rightBytes);
}

function validPathParameter(value, pattern) {
  return typeof value === "string" && pattern.test(value);
}

function deploymentMatches(deployment, owner, repo, pullRequest, headSha) {
  const metadata = deployment && deployment.meta;
  if (!metadata || typeof metadata !== "object") return false;

  const deploymentOwner = metadata.githubCommitOrg || metadata.githubOrg;
  const deploymentRepo = metadata.githubCommitRepo || metadata.githubRepo;
  return deployment.state === "READY"
    && deployment.target === null
    && String(metadata.githubPrId || "") === String(pullRequest)
    && typeof metadata.githubCommitSha === "string"
    && /^[a-f0-9]{40,64}$/i.test(metadata.githubCommitSha)
    && metadata.githubCommitSha.toLowerCase() === headSha.toLowerCase()
    && typeof deploymentOwner === "string"
    && deploymentOwner.toLowerCase() === owner.toLowerCase()
    && typeof deploymentRepo === "string"
    && deploymentRepo.toLowerCase() === repo.toLowerCase();
}

function deploymentOrigin(deployment) {
  if (
    typeof deployment.url !== "string"
    || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+vercel\.app$/i.test(deployment.url)
  ) {
    return null;
  }
  return `https://${deployment.url.toLowerCase()}`;
}

function signAttestation(attestation, key) {
  const payload = {};
  for (const field of SIGNED_FIELDS) payload[field] = attestation[field];
  const canonical = JSON.stringify(
    Object.fromEntries(Object.entries(payload).sort(([left], [right]) => left.localeCompare(right))),
  );
  return crypto.createHmac("sha256", key).update(canonical, "ascii").digest("hex");
}

async function listDeployments({ projectId, teamId, token, headSha }) {
  const url = new URL("https://api.vercel.com/v7/deployments");
  url.searchParams.set("projectId", projectId);
  url.searchParams.set("state", "READY");
  url.searchParams.set("sha", headSha);
  url.searchParams.set("limit", "100");
  if (teamId) url.searchParams.set("teamId", teamId);

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) throw new Error("deployment lookup failed");
  const body = await response.json();
  if (!body || !Array.isArray(body.deployments)) {
    throw new Error("deployment response was malformed");
  }
  return body.deployments;
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return respond(res, 405, { error: "method_not_allowed" });
  }

  const { owner, repo, pull_request: pullRequestValue } = req.query || {};
  const headSha = req.query && req.query.head_sha;
  if (
    !validPathParameter(owner, /^[A-Za-z0-9_.-]{1,100}$/)
    || !validPathParameter(repo, /^[A-Za-z0-9_.-]{1,100}$/)
    || !validPathParameter(pullRequestValue, /^[1-9][0-9]{0,8}$/)
    || !validPathParameter(headSha, /^[a-f0-9]{40,64}$/i)
  ) {
    return respond(res, 400, { error: "invalid_request" });
  }
  if (`${owner}/${repo}`.toLowerCase() !== REPOSITORY) {
    return respond(res, 404, { error: "not_found" });
  }

  const expectedToken = process.env.GREGORFORGE_PREVIEW_PROVIDER_TOKEN || "";
  if (Buffer.byteLength(expectedToken, "utf8") < 32) {
    return respond(res, 503, { error: "provider_not_configured" });
  }
  const suppliedAuthorization = req.headers && req.headers.authorization;
  const suppliedToken = typeof suppliedAuthorization === "string"
    && suppliedAuthorization.startsWith("Bearer ")
    ? suppliedAuthorization.slice("Bearer ".length)
    : "";
  if (!expectedToken || !secureEqual(suppliedToken, expectedToken)) {
    return respond(res, 401, { error: "unauthorized" });
  }

  const signingKey = process.env.GREGORFORGE_PREVIEW_ATTESTATION_KEY || "";
  const vercelToken = process.env.VERCEL_TOKEN || "";
  const projectId = process.env.VERCEL_PROJECT_ID || "";
  const teamId = process.env.VERCEL_TEAM_ID || "";
  if (Buffer.byteLength(signingKey, "utf8") < 32 || !vercelToken || !projectId) {
    return respond(res, 503, { error: "provider_not_configured" });
  }

  try {
    const deployments = await listDeployments({
      projectId,
      teamId,
      token: vercelToken,
      headSha,
    });
    const matching = deployments
      .filter((deployment) => deploymentMatches(
        deployment,
        owner,
        repo,
        pullRequestValue,
        headSha,
      ))
      .sort((left, right) => Number(right.createdAt || right.created || 0) - Number(left.createdAt || left.created || 0));
    const deployment = matching.find((candidate) => deploymentOrigin(candidate));
    if (!deployment) return respond(res, 404, { error: "ready_preview_not_found" });

    const origin = deploymentOrigin(deployment);
    const attestation = {
      repository: REPOSITORY,
      pull_request: Number(pullRequestValue),
      head_sha: deployment.meta.githubCommitSha.toLowerCase(),
      preview_id: deployment.uid,
      origin,
      expires_at: new Date(Date.now() + ATTESTATION_TTL_MS).toISOString(),
      status: "ready",
    };
    if (
      typeof attestation.preview_id !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(attestation.preview_id)
    ) {
      return respond(res, 502, { error: "invalid_deployment_identity" });
    }
    attestation.signature = signAttestation(attestation, signingKey);
    return respond(res, 200, attestation);
  } catch {
    return respond(res, 502, { error: "deployment_lookup_failed" });
  }
};

module.exports.signAttestation = signAttestation;
