import path from "node:path";
import { mkdir, readFile, realpath, rename, stat, writeFile } from "node:fs/promises";

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { jsonResult } from "openclaw/plugin-sdk/tool-results";

const FLOW_START_PARAMETERS = {
  type: "object",
  additionalProperties: false,
  required: ["run_id", "mode"],
  properties: {
    run_id: { type: "string", pattern: "^run_[A-Za-z0-9_-]+$" },
    mode: {
      type: "string",
      enum: [
        "structured-ingest",
        "hourly-discovery",
        "watch-refresh",
        "daily-brief",
        "evaluation"
      ]
    }
  }
};

const FLOW_FINISH_PARAMETERS = {
  type: "object",
  additionalProperties: false,
  required: ["flow_id", "expected_revision", "run_id", "report_id"],
  properties: {
    flow_id: { type: "string", minLength: 1, maxLength: 200 },
    expected_revision: { type: "integer", minimum: 0 },
    run_id: { type: "string", pattern: "^run_[A-Za-z0-9_-]+$" },
    report_id: { type: "string", pattern: "^rp_[A-Za-z0-9_-]+$" }
  }
};

const DELIVERY_PARAMETERS = {
  type: "object",
  additionalProperties: false,
  required: ["report_id", "idempotency_key", "summary", "html_path"],
  properties: {
    report_id: { type: "string", pattern: "^rp_[A-Za-z0-9_-]+$" },
    idempotency_key: {
      type: "string",
      pattern: "^idem_[A-Za-z0-9_-]{32,128}$"
    },
    summary: { type: "string", minLength: 1, maxLength: 2000 },
    html_path: { type: "string", pattern: "^/", maxLength: 1000 }
  }
};

function pluginConfig(api) {
  const value = api.pluginConfig ?? {};
  return {
    reportRoot: String(value.reportRoot ?? ""),
    discordChannelId: String(value.discordChannelId ?? ""),
    discordAccountId: String(value.discordAccountId ?? ""),
    externalDeliveryEnabled: value.externalDeliveryEnabled === true
  };
}

function flowStartTool(api, toolContext) {
  return {
    name: "research_flow_start",
    label: "Start Telemetry Research TaskFlow",
    description: "Create one managed TaskFlow for a reviewed Telemetry Research run.",
    parameters: FLOW_START_PARAMETERS,
    async execute(_toolCallId, raw) {
      const params = raw;
      const taskFlow = api.runtime.tasks.flow.fromToolContext(toolContext);
      const created = taskFlow.createManaged({
        controllerId: "telemetry-research/orchestrator-v1",
        goal: `Run Telemetry Research ${params.mode}`,
        currentStep: "planned",
        stateJson: {
          runId: params.run_id,
          mode: params.mode,
          sourceContentIncluded: false
        }
      });
      return jsonResult({
        flow_id: created.flowId,
        revision: created.revision,
        status: created.status,
        current_step: created.currentStep
      });
    }
  };
}

function flowFinishTool(api, toolContext) {
  return {
    name: "research_flow_finish",
    label: "Finish Telemetry Research TaskFlow",
    description: "Finish a managed Telemetry Research TaskFlow with typed object references only.",
    parameters: FLOW_FINISH_PARAMETERS,
    async execute(_toolCallId, raw) {
      const params = raw;
      const taskFlow = api.runtime.tasks.flow.fromToolContext(toolContext);
      const finished = taskFlow.finish({
        flowId: params.flow_id,
        expectedRevision: params.expected_revision,
        stateJson: {
          runId: params.run_id,
          reportId: params.report_id,
          sourceContentIncluded: false
        }
      });
      if (!finished.applied) {
        return jsonResult({
          ok: false,
          code: finished.code ?? "FLOW_FINISH_REJECTED"
        });
      }
      return jsonResult({
        ok: true,
        flow_id: finished.flow.flowId,
        revision: finished.flow.revision,
        status: finished.flow.status
      });
    }
  };
}

function deliveryTool(api) {
  return {
    name: "research_delivery_send",
    label: "Send Verified Telemetry Research Report",
    description: "Send one verified report to the single configured Discord channel.",
    parameters: DELIVERY_PARAMETERS,
    async execute(_toolCallId, raw) {
      const params = raw;
      const config = pluginConfig(api);
      if (!config.externalDeliveryEnabled) {
        return jsonResult({ ok: false, code: "EXTERNAL_DELIVERY_DISABLED" });
      }
      const validated = await validateReportFiles(config, params);
      if (!validated.ok) return jsonResult(validated);
      const send = (await api.runtime.channel.outbound.loadAdapter("discord"))?.sendMedia;
      if (!send) {
        return jsonResult({ ok: false, code: "DISCORD_ADAPTER_UNAVAILABLE" });
      }
      const receiptDirectory = path.join(validated.reportRoot, ".delivery-receipts");
      await mkdir(receiptDirectory, { recursive: true, mode: 0o700 });
      const receiptPath = path.join(receiptDirectory, `${params.idempotency_key}.json`);
      const existing = await readReceipt(receiptPath);
      if (existing) {
        if (!sameDelivery(existing, params, config.discordChannelId)) {
          return jsonResult({ ok: false, code: "DELIVERY_IDEMPOTENCY_CONFLICT" });
        }
        if (existing.status !== "delivered") {
          return jsonResult({ ok: false, code: "DELIVERY_STATUS_UNKNOWN" });
        }
        return jsonResult({
          ok: true,
          duplicate: true,
          delivery: existing
        });
      }
      const target = `channel:${config.discordChannelId}`;
      const pending = {
        status: "pending",
        report_id: params.report_id,
        destination: `discord:${target}`,
        idempotency_key: params.idempotency_key,
        created_at: new Date().toISOString()
      };
      try {
        await writeFile(receiptPath, `${JSON.stringify(pending)}\n`, {
          encoding: "utf8",
          flag: "wx",
          mode: 0o600
        });
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        const raced = await readReceipt(receiptPath);
        if (!raced || !sameDelivery(raced, params, config.discordChannelId)) {
          return jsonResult({ ok: false, code: "DELIVERY_IDEMPOTENCY_CONFLICT" });
        }
        return jsonResult({
          ok: raced.status === "delivered",
          duplicate: raced.status === "delivered",
          code: raced.status === "delivered" ? undefined : "DELIVERY_STATUS_UNKNOWN",
          delivery: raced
        });
      }
      await send({
        cfg: api.config,
        to: target,
        text: params.summary,
        mediaUrl: validated.htmlPath,
        mediaLocalRoots: [validated.reportRoot],
        accountId: config.discordAccountId
      });
      const receipt = {
        status: "delivered",
        report_id: params.report_id,
        destination: `discord:${target}`,
        idempotency_key: params.idempotency_key,
        delivered_at: new Date().toISOString()
      };
      const stagedReceiptPath = `${receiptPath}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(stagedReceiptPath, `${JSON.stringify(receipt)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600
      });
      await rename(stagedReceiptPath, receiptPath);
      return jsonResult({ ok: true, duplicate: false, delivery: receipt });
    }
  };
}

async function readReceipt(receiptPath) {
  try {
    const value = JSON.parse(await readFile(receiptPath, "utf8"));
    return value && typeof value === "object" ? value : null;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function sameDelivery(receipt, params, discordChannelId) {
  return (
    receipt.report_id === params.report_id &&
    receipt.idempotency_key === params.idempotency_key &&
    receipt.destination === `discord:channel:${discordChannelId}`
  );
}

async function validateReportFiles(config, params) {
  if (!config.reportRoot) return { ok: false, code: "REPORT_ROOT_NOT_CONFIGURED" };
  let reportRoot;
  let htmlPath;
  try {
    reportRoot = await realpath(config.reportRoot);
    htmlPath = await realpath(params.html_path);
  } catch {
    return { ok: false, code: "REPORT_PATH_NOT_FOUND" };
  }
  const relative = path.relative(reportRoot, htmlPath);
  if (relative.startsWith("..") || path.isAbsolute(relative) || path.extname(htmlPath) !== ".html") {
    return { ok: false, code: "REPORT_PATH_OUTSIDE_ROOT" };
  }
  const htmlStats = await stat(htmlPath);
  if (!htmlStats.isFile() || htmlStats.size > 10_485_760) {
    return { ok: false, code: "REPORT_HTML_INVALID" };
  }
  const reportJsonPath = htmlPath.slice(0, -5) + ".json";
  let report;
  try {
    report = JSON.parse(await readFile(reportJsonPath, "utf8"));
  } catch {
    return { ok: false, code: "REPORT_JSON_INVALID" };
  }
  if (report.report_id !== params.report_id) {
    return { ok: false, code: "REPORT_ID_MISMATCH" };
  }
  const deliveryPlanPath = htmlPath.slice(0, -5) + ".delivery.json";
  let deliveryPlan;
  let plannedHtmlPath;
  try {
    deliveryPlan = JSON.parse(await readFile(deliveryPlanPath, "utf8"));
    plannedHtmlPath = await realpath(deliveryPlan.html_path);
  } catch {
    return { ok: false, code: "DELIVERY_PLAN_INVALID" };
  }
  const expectedDestination = `discord:channel:${config.discordChannelId}`;
  if (
    deliveryPlan.report_id !== params.report_id ||
    deliveryPlan.idempotency_key !== params.idempotency_key ||
    deliveryPlan.summary !== params.summary ||
    plannedHtmlPath !== htmlPath ||
    deliveryPlan.destination !== expectedDestination
  ) {
    return { ok: false, code: "DELIVERY_PLAN_MISMATCH" };
  }
  if (
    report.verification?.all_claims_cited !== true ||
    report.verification?.all_claims_verified !== true
  ) {
    return { ok: false, code: "REPORT_NOT_VERIFIED" };
  }
  const claims = (report.findings ?? []).flatMap((finding) => finding.claims ?? []);
  if (claims.some((claim) => claim.verification_status !== "verified")) {
    return { ok: false, code: "REPORT_CLAIM_NOT_VERIFIED" };
  }
  return { ok: true, reportRoot, htmlPath };
}

export default definePluginEntry({
  id: "telemetry-research-boundary",
  name: "Telemetry Research Boundary",
  description: "Narrow TaskFlow lifecycle and verified Discord delivery.",
  register(api) {
    api.registerTool((ctx) => flowStartTool(api, ctx), {
      names: ["research_flow_start"]
    });
    api.registerTool((ctx) => flowFinishTool(api, ctx), {
      names: ["research_flow_finish"]
    });
    api.registerTool(deliveryTool(api), {
      name: "research_delivery_send"
    });
  }
});
