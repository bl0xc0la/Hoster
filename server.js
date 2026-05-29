// server.js
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: "hoster-dev-secret",
    resave: false,
    saveUninitialized: false,
  })
);

const state = {
  users: new Map(),      // username -> { id, username, passwordHash, salt }
  sites: new Map(),      // slug -> site
  domains: new Map(),    // custom domain -> slug
};

function slugify(input) {
  return String(input || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function randomId() {
  return crypto.randomBytes(12).toString("hex");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password), salt, 32).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const attempt = crypto.scryptSync(String(password), salt, 32).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(attempt), Buffer.from(hash));
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Login required" });
  }
  next();
}

function currentUser(req) {
  if (!req.session.userId) return null;
  for (const user of state.users.values()) {
    if (user.id === req.session.userId) return user;
  }
  return null;
}

function userSites(userId) {
  return [...state.sites.values()]
    .filter((site) => site.ownerId === userId)
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

function buildPage(site) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${escapeHtml(site.title || site.slug)} - Hoster</title>
<style>
${site.css || ""}
</style>
</head>
<body>
${site.html || ""}
<script>
${site.js || ""}
</script>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function resolveSiteFromHost(hostname) {
  const host = String(hostname || "").split(":")[0].toLowerCase();
  if (!host || host === "localhost" || host === "127.0.0.1") return null;

  if (state.domains.has(host)) {
    const slug = state.domains.get(host);
    return state.sites.get(slug) || null;
  }

  const parts = host.split(".");
  if (parts.length >= 3) {
    const subdomain = parts[0];
    if (state.sites.has(subdomain)) return state.sites.get(subdomain);
  }

  if (state.sites.has(host)) return state.sites.get(host);
  return null;
}

function siteResponse(site, req, res) {
  site.views += 1;
  site.lastViewedAt = Date.now();
  res.type("html").send(buildPage(site));
}

app.get("/api/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.json({ user: null });
  res.json({ user: { username: user.username } });
});

app.post("/api/register", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (username.length < 3) {
    return res.status(400).json({ error: "Username must be at least 3 characters." });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: "Password must be at least 4 characters." });
  }
  if (state.users.has(username)) {
    return res.status(400).json({ error: "Username already exists." });
  }

  const { salt, hash } = hashPassword(password);
  const user = {
    id: randomId(),
    username,
    salt,
    passwordHash: hash,
  };

  state.users.set(username, user);
  req.session.userId = user.id;

  res.json({ success: true, user: { username } });
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = state.users.get(username);

  if (!user) return res.status(400).json({ error: "User not found." });
  if (!verifyPassword(password, user.salt, user.passwordHash)) {
    return res.status(400).json({ error: "Invalid password." });
  }

  req.session.userId = user.id;
  res.json({ success: true, user: { username } });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/api/sites", requireAuth, (req, res) => {
  const user = currentUser(req);
  res.json({
    sites: userSites(user.id).map((site) => ({
      slug: site.slug,
      title: site.title,
      views: site.views,
      domains: site.domains,
      updatedAt: site.updatedAt,
    })),
  });
});

app.post("/api/sites", requireAuth, (req, res) => {
  const user = currentUser(req);
  const title = String(req.body.title || "Untitled Site").trim();
  const desiredSlug = slugify(req.body.slug || title);
  const slug = desiredSlug || `site-${randomId().slice(0, 6)}`;

  if (state.sites.has(slug)) {
    return res.status(400).json({ error: "That site name is already taken." });
  }

  const site = {
    id: randomId(),
    ownerId: user.id,
    slug,
    title,
    html: req.body.html || "<main class=\"wrap\"><h1>Hello from Hoster</h1></main>",
    css: req.body.css || "body{font-family:system-ui;background:#0b0b10;color:#fff;margin:0}.wrap{padding:48px}",
    js: req.body.js || "",
    views: 0,
    domains: [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
    lastViewedAt: null,
  };

  state.sites.set(slug, site);
  res.json({
    success: true,
    site: {
      slug: site.slug,
      title: site.title,
      views: site.views,
      domains: site.domains,
      html: site.html,
      css: site.css,
      js: site.js,
    },
  });
});

app.get("/api/sites/:slug", requireAuth, (req, res) => {
  const user = currentUser(req);
  const site = state.sites.get(req.params.slug);

  if (!site || site.ownerId !== user.id) {
    return res.status(404).json({ error: "Site not found." });
  }

  res.json({
    site: {
      slug: site.slug,
      title: site.title,
      html: site.html,
      css: site.css,
      js: site.js,
      views: site.views,
      domains: site.domains,
      updatedAt: site.updatedAt,
    },
  });
});

app.put("/api/sites/:slug", requireAuth, (req, res) => {
  const user = currentUser(req);
  const site = state.sites.get(req.params.slug);

  if (!site || site.ownerId !== user.id) {
    return res.status(404).json({ error: "Site not found." });
  }

  site.title = String(req.body.title || site.title).trim();
  site.html = String(req.body.html || "");
  site.css = String(req.body.css || "");
  site.js = String(req.body.js || "");
  site.updatedAt = Date.now();

  res.json({ success: true });
});

app.post("/api/sites/:slug/deploy", requireAuth, (req, res) => {
  const user = currentUser(req);
  const site = state.sites.get(req.params.slug);

  if (!site || site.ownerId !== user.id) {
    return res.status(404).json({ error: "Site not found." });
  }

  const domain = String(req.body.domain || "").trim().toLowerCase();
  if (domain) {
    state.domains.set(domain, site.slug);
    if (!site.domains.includes(domain)) site.domains.push(domain);
  }

  const hostSubdomain = `${site.slug}.hoster.localhost`;
  res.json({
    success: true,
    subdomain: hostSubdomain,
    customDomain: domain || null,
    publishedUrl: `http://${hostSubdomain}:${PORT}`.replace(`:${PORT}`, PORT === 80 ? "" : `:${PORT}`),
  });
});

app.get("/api/sites/:slug/analytics", requireAuth, (req, res) => {
  const user = currentUser(req);
  const site = state.sites.get(req.params.slug);

  if (!site || site.ownerId !== user.id) {
    return res.status(404).json({ error: "Site not found." });
  }

  res.json({
    views: site.views,
    domains: site.domains,
    updatedAt: site.updatedAt,
    lastViewedAt: site.lastViewedAt,
  });
});

app.get("/view/:slug", (req, res) => {
  const site = state.sites.get(req.params.slug);
  if (!site) return res.status(404).send("Website not found");
  return siteResponse(site, req, res);
});

app.get(["/", "/editor", "/dashboard"], (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((req, res, next) => {
  if (req.path.startsWith("/api/") || req.path.startsWith("/view/")) return next();

  const site = resolveSiteFromHost(req.hostname);
  if (site) return siteResponse(site, req, res);

  if (req.method === "GET") {
    return res.sendFile(path.join(__dirname, "index.html"));
  }
  next();
});

app.use((req, res) => {
  res.status(404).send("Not found");
});

app.listen(PORT, () => {
  console.log(`Hoster running on http://localhost:${PORT}`);
});
