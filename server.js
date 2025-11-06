// server/src/index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Onfido
const ONFIDO_API_TOKEN = process.env.ONFIDO_API_TOKEN;
const ONFIDO_API_BASE = process.env.ONFIDO_API_BASE || "https://api.us.onfido.com";
const ONFIDO_API_VERSION = "v3.6";
const ONFIDO_WEBHOOK_SECRET = process.env.ONFIDO_WEBHOOK_SECRET || ""; // opțional

if (!ONFIDO_API_TOKEN) {
  console.error("Lipsește ONFIDO_API_TOKEN în server/.env");
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: "2mb" })); // pentru toate rutele non-webhook

// --- stocare in-memory pentru ultimele webhook-uri (opțional, util de debug / demo) ---
const webhookStore = new Map(); // key: workflow_run_id, value: payload map + timestamp

// Health
app.get("/healthz", (_req, res) => res.send("ok"));

// Helper fetch Onfido (Node 18+ are fetch nativ)
async function onfidoFetch(pathname, opts = {}) {
  const url = `${ONFIDO_API_BASE}/${ONFIDO_API_VERSION}${pathname}`;
  const headers = {
    Authorization: `Token token=${ONFIDO_API_TOKEN}`,
    Accept: "application/json",
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  const res = await fetch(url, { ...opts, headers });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const msg = json?.error?.message || json?.message || JSON.stringify(json);
    const err = new Error(msg || `Onfido error ${res.status}`);
    err.status = res.status;
    err.payload = json;
    throw err;
  }
  return json;
}

/**
 * POST /api/applicants
 * Body: { first_name, last_name, email }
 */
app.post("/api/applicants", async (req, res) => {
  try {
    const { first_name, last_name, email } = req.body || {};
    const payload = { first_name, last_name, email };
    const applicant = await onfidoFetch(`/applicants`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    res.json(applicant);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message, details: e.payload });
  }
});

/**
 * POST /api/workflow_runs
 * Body: { workflow_id, applicant_id }
 * Returnează inclusiv sdk_token
 */
app.post("/api/workflow_runs", async (req, res) => {
  try {
    const { workflow_id, applicant_id } = req.body || {};
    const run = await onfidoFetch(`/workflow_runs`, {
      method: "POST",
      body: JSON.stringify({ workflow_id, applicant_id }),
    });
    res.json(run);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message, details: e.payload });
  }
});

/**
 * GET /api/workflow_runs/:id
 * Combină status + output cu numele applicantului
 */
app.get("/api/workflow_runs/:id", async (req, res) => {
  try {
    const runId = req.params.id;
    const run = await onfidoFetch(`/workflow_runs/${encodeURIComponent(runId)}`, {
      method: "GET",
    });

    const status = run?.status || null;
    const output = run?.output || {};
    const applicantId = run?.applicant_id || null;

    let firstName = null;
    let lastName = null;

    if (applicantId) {
      try {
        const applicant = await onfidoFetch(`/applicants/${encodeURIComponent(applicantId)}`, {
          method: "GET",
        });
        firstName = applicant?.first_name || null;
        lastName = applicant?.last_name || null;
      } catch {}
    }

    const mapped = {
      status,
      first_name: firstName,
      last_name: lastName,
      gender: output?.gender ?? null,
      date_of_birth: output?.dob ?? null,
      document_type: output?.document_type ?? null,
      document_number: output?.document_number ?? null,
      date_expiry: output?.date_expiry ?? null,
      workflow_run_id: run?.id || runId,
      applicant_id: applicantId,
      dashboard_url: run?.dashboard_url || null,
    };

    res.json(mapped);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message, details: e.payload });
  }
});

/* =========================
   WEBHOOK Onfido (opțional)
   URL pt. Onfido: https://marlon-app-2.onrender.com/webhook/onfido
   ========================= */

// pentru verificare semnătură trebuie corpul brut, nu JSON parsat
app.post(
  "/webhook/onfido",
  express.raw({ type: "application/json", limit: "2mb" }),
  (req, res) => {
    try {
      const raw = req.body; // Buffer
      const sigHeader = req.header("X-SHA2-Signature"); // header-ul Onfido
      // Dacă ai pus ONFIDO_WEBHOOK_SECRET, verifică semnătura
      if (ONFIDO_WEBHOOK_SECRET) {
        if (!sigHeader) {
          return res.status(400).send("missing signature");
        }
        const expected = crypto
          .createHmac("sha256", ONFIDO_WEBHOOK_SECRET)
          .update(raw)
          .digest("hex");
        if (expected !== sigHeader) {
          return res.status(400).send("invalid signature");
        }
      }

      // Parsează payload-ul
      let payload = {};
      try {
        payload = JSON.parse(raw.toString("utf8"));
      } catch {
        return res.status(400).send("invalid json");
      }

      // Extrage ce te interesează din payload (după exemplul tău)
      const resrc = payload?.payload?.resource || {};
      const output = resrc?.output || {};
      const runId =
        resrc?.id ||
        payload?.payload?.object?.id ||
        payload?.object?.id ||
        null;

      const mapped = {
        workflow_run_id: runId,
        status: resrc?.status || payload?.payload?.object?.status || null,
        first_name: null, // numele îl luăm de obicei din applicant API, aici nu vine
        last_name: null,
        gender: output?.gender ?? null,
        date_of_birth: output?.dob ?? null,
        document_type: output?.document_type ?? null,
        document_number: output?.document_number ?? null,
        date_expiry: output?.date_expiry ?? null,
        applicant_id: resrc?.applicant_id || null,
        received_at: new Date().toISOString(),
      };

      if (runId) {
        webhookStore.set(runId, mapped);
      }

      // răspunde rapid 200 la Onfido
      res.status(200).send("ok");
    } catch (err) {
      console.error("Webhook error:", err);
      res.status(200).send("ok"); // Onfido recomandă 200 chiar și pe erori interne, ca să nu reîncerce agresiv
    }
  }
);

// endpoint mic de debug ca să vezi ce a ajuns prin webhook
app.get("/api/webhook_runs/:id", (req, res) => {
  const runId = req.params.id;
  const data = webhookStore.get(runId);
  if (!data) return res.status(404).json({ message: "not found" });
  res.json(data);
});

/**
 * Static frontend în producție
 * Dacă există client/dist, îl servim pe același domeniu
 */
const clientDist = path.resolve(__dirname, "../../client/dist");
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get("*", (_req, res) => {
    res.sendFile(path.join(clientDist, "index.html"));
  });
}

app.listen(PORT, () => {
  console.log(`API pornit pe http://localhost:${PORT}`);
});
