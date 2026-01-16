const http = require("http");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = process.env.PORT || 3000;

const json = (res, status, payload) => {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
  });
  res.end(body);
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
    });
    req.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });

const notFound = (res) => {
  json(res, 404, { ok: false, error: "Not found" });
};

const badRequest = (res, message) => {
  json(res, 400, { ok: false, error: message });
};

const sessionId = () => `sess_${crypto.randomBytes(4).toString("hex")}`;
const proofToken = () => `proof_${crypto.randomBytes(6).toString("hex")}`;
const keyToken = () => `KEY-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

const routes = {
  "GET /api/health": async (_req, res) =>
    json(res, 200, { ok: true, status: "healthy", time: new Date().toISOString() }),

  "GET /api/config": async (_req, res) =>
    json(res, 200, {
      ok: true,
      checkpoints: 3,
      cooldownSeconds: 900,
      providers: ["shortlink", "ad", "captcha"],
    }),

  "POST /api/session/start": async (_req, res) =>
    json(res, 200, {
      ok: true,
      sessionId: sessionId(),
      nextCheckpoint: 1,
      expiresIn: 600,
    }),

  "GET /api/session/status": async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const session = url.searchParams.get("sessionId");
    if (!session) {
      return badRequest(res, "sessionId is required");
    }
    return json(res, 200, {
      ok: true,
      sessionId: session,
      checkpoint: 1,
      completed: false,
    });
  },

  "POST /api/session/refresh": async (_req, res) =>
    json(res, 200, {
      ok: true,
      sessionId: sessionId(),
      expiresIn: 600,
    }),

  "GET /api/checkpoint/next": async (_req, res) =>
    json(res, 200, {
      ok: true,
      checkpoint: 1,
      provider: "shortlink",
      proofToken: proofToken(),
    }),

  "POST /api/checkpoint/complete": async (req, res) => {
    const body = await readBody(req).catch(() => null);
    if (!body) {
      return badRequest(res, "Invalid JSON body");
    }
    return json(res, 200, {
      ok: true,
      received: body,
      nextCheckpoint: 2,
      nextUrl: "/checkpoint/2",
      expiresIn: 120,
    });
  },

  "POST /api/checkpoint/verify": async (req, res) => {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.proofToken) {
      return badRequest(res, "proofToken is required");
    }
    return json(res, 200, {
      ok: true,
      verified: true,
      proofToken: body.proofToken,
    });
  },

  "GET /api/key": async (_req, res) =>
    json(res, 200, {
      ok: true,
      key: keyToken(),
      expiresIn: 900,
    }),

  "POST /api/key/validate": async (req, res) => {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.key) {
      return badRequest(res, "key is required");
    }
    return json(res, 200, {
      ok: true,
      valid: true,
      key: body.key,
    });
  },

  "POST /api/key/revoke": async (req, res) => {
    const body = await readBody(req).catch(() => null);
    if (!body || !body.key) {
      return badRequest(res, "key is required");
    }
    return json(res, 200, {
      ok: true,
      revoked: true,
      key: body.key,
    });
  },
};

const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    res.end();
    return;
  }

  const pathname = url.split("?")[0];
  const key = `${method} ${pathname}`;
  const handler = routes[key];
  if (!handler) {
    return notFound(res);
  }
  try {
    await handler(req, res);
  } catch (error) {
    json(res, 500, { ok: false, error: "Server error" });
  }
});

server.listen(PORT, () => {
  console.log(`PulseKeys API listening on http://localhost:${PORT}`);
});
