const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;

// SECRETS
const JWT_SECRET = process.env.JWT_SECRET || "sda_super_secret_key_change_me_12345";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "sda_admin_secret_key_change_me_67890";

const db = new sqlite3.Database("./smart_users.db");

// ============================================================
// FUNCIÓN PARA FORMATEAR TIEMPO RESTANTE
// ============================================================
function formatRemaining(ms) {
  if (ms <= 0) return 'EXPIRADA';
  const days = Math.floor(ms / (1000 * 60 * 60 * 24));
  const hours = Math.floor((ms % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((ms % (1000 * 60)) / 1000);
  
  return `${days}D : ${hours.toString().padStart(2, '0')}H : ${minutes.toString().padStart(2, '0')}M : ${seconds.toString().padStart(2, '0')}S`;
}

// ============================================================
// INICIALIZAR TABLAS
// ============================================================
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      active INTEGER DEFAULT 1,
      can_use_app INTEGER DEFAULT 1,
      device_id TEXT,
      expires_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      last_login TEXT
    )
  `);

  const adminEmail = "admin@smart.local";
  const adminPassword = "Admin123456";
  const adminHash = bcrypt.hashSync(adminPassword, 10);

  db.run(
    `INSERT OR IGNORE INTO admins (email, password_hash, role) VALUES (?, ?, 'admin')`,
    [adminEmail, adminHash]
  );
});

// ============================================================
// MIDDLEWARES
// ============================================================
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ success: false, message: "Missing token" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}

function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ success: false, message: "Missing admin token" });
  }

  try {
    const decoded = jwt.verify(token, ADMIN_SECRET);
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: "Invalid admin token" });
  }
}

// ============================================================
// ENDPOINTS PARA APP ANDROID
// ============================================================

app.post("/api/auth/login", (req, res) => {
  const { email, password, deviceId } = req.body;

  if (!email || !password || !deviceId) {
    return res.status(400).json({ success: false, message: "email, password and deviceId are required" });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const passwordOk = bcrypt.compareSync(password, user.password_hash);
    if (!passwordOk) return res.status(401).json({ success: false, message: "Invalid credentials" });

    if (user.active !== 1 || user.can_use_app !== 1) {
      return res.status(403).json({ success: false, message: "User not allowed" });
    }

    const today = new Date();
    const expiresAt = user.expires_at ? new Date(user.expires_at) : null;

    if (expiresAt && expiresAt < today) {
      return res.status(403).json({ success: false, message: "License expired" });
    }

    if (!user.device_id) {
      db.run("UPDATE users SET device_id = ? WHERE id = ?", [deviceId, user.id]);
    } else if (user.device_id !== deviceId) {
      return res.status(403).json({ success: false, message: "This account is already linked to another device" });
    }

    db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);

    const token = jwt.sign(
      { userId: user.id, email: user.email, deviceId: deviceId },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt.getTime() - today.getTime()) / 1000)) : 0;

    return res.json({
      success: true,
      token,
      expiresAt: user.expires_at,
      secondsRemaining,
      displayRemaining: formatRemaining(secondsRemaining * 1000),
      user: {
        email: user.email,
        active: user.active === 1,
        canUseApp: user.can_use_app === 1
      }
    });
  });
});

app.get("/api/auth/session-status", verifyToken, (req, res) => {
  const userId = req.user.userId;
  const deviceId = req.user.deviceId;

  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const now = Date.now();
    const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
    const isExpired = expiresAt && expiresAt < now;
    const isBlocked = user.can_use_app !== 1 || user.active !== 1;
    const deviceValid = !user.device_id || user.device_id === deviceId;

    const allowed = !isExpired && !isBlocked && deviceValid;
    const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;

    res.json({
      success: true,
      allowed,
      expired: isExpired,
      blocked: isBlocked,
      deviceValid,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      secondsRemaining,
      displayRemaining: formatRemaining(secondsRemaining * 1000)
    });
  });
});

app.post("/api/auth/can-activate", verifyToken, (req, res) => {
  const userId = req.user.userId;
  const deviceId = req.user.deviceId;

  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      return res.json({ canActivate: false, message: "User not found" });
    }

    const now = Date.now();
    const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
    const isExpired = expiresAt && expiresAt < now;
    const isBlocked = user.can_use_app !== 1 || user.active !== 1;
    const deviceValid = !user.device_id || user.device_id === deviceId;

    const canActivate = !isExpired && !isBlocked && deviceValid;
    const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;

    let message = "OK";
    if (isExpired) message = "License expired";
    else if (isBlocked) message = "User blocked";
    else if (!deviceValid) message = "Account linked to another device";

    res.json({
      canActivate,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      secondsRemaining,
      displayRemaining: formatRemaining(secondsRemaining * 1000),
      message
    });
  });
});

app.get("/api/auth/validate", verifyToken, (req, res) => {
  const userId = req.user.userId;
  const deviceId = req.user.deviceId;

  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ valid: false, message: "User not found" });
    }

    const now = Date.now();
    const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
    const isExpired = expiresAt && expiresAt < now;
    const isBlocked = user.can_use_app !== 1 || user.active !== 1;
    const deviceValid = !user.device_id || user.device_id === deviceId;

    if (isExpired || isBlocked || !deviceValid) {
      return res.status(401).json({
        valid: false,
        message: isExpired ? "License expired" : (isBlocked ? "User blocked" : "Invalid device")
      });
    }

    const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;

    res.json({
      valid: true,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      secondsRemaining,
      displayRemaining: formatRemaining(secondsRemaining * 1000)
    });
  });
});

// ============================================================
// ENDPOINTS DE ADMIN
// ============================================================

app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM admins WHERE email = ?", [email], (err, admin) => {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    if (!admin) return res.status(401).json({ success: false, message: "Invalid admin credentials" });

    const ok = bcrypt.compareSync(password, admin.password_hash);
    if (!ok) return res.status(401).json({ success: false, message: "Invalid admin credentials" });

    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      ADMIN_SECRET,
      { expiresIn: "12h" }
    );

    return res.json({ success: true, token, admin: { email: admin.email, role: admin.role } });
  });
});

app.post("/api/admin/create-user", verifyAdmin, (req, res) => {
  const { email, password, expiresAt } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "email and password are required" });
  }

  const hash = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (email, password_hash, active, can_use_app, expires_at) VALUES (?, ?, 1, 1, ?)`,
    [email, hash, expiresAt || null],
    function (err) {
      if (err) return res.status(400).json({ success: false, message: "User already exists or invalid data" });
      return res.json({ success: true, message: "User created", userId: this.lastID });
    }
  );
});

app.get("/api/admin/users", verifyAdmin, (req, res) => {
  db.all(`SELECT id, email, active, can_use_app, device_id, expires_at, created_at, last_login FROM users ORDER BY id DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: "Database error" });
      return res.json({ success: true, users: rows });
    }
  );
});

app.post("/api/admin/block-user", verifyAdmin, (req, res) => {
  const { email } = req.body;
  db.run("UPDATE users SET active = 0, can_use_app = 0 WHERE email = ?", [email], function (err) {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    return res.json({ success: true, message: "User blocked", changes: this.changes });
  });
});

app.post("/api/admin/activate-user", verifyAdmin, (req, res) => {
  const { email } = req.body;
  db.run("UPDATE users SET active = 1, can_use_app = 1 WHERE email = ?", [email], function (err) {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    return res.json({ success: true, message: "User activated", changes: this.changes });
  });
});

app.post("/api/admin/reset-device", verifyAdmin, (req, res) => {
  const { email } = req.body;
  db.run("UPDATE users SET device_id = NULL WHERE email = ?", [email], function (err) {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    return res.json({ success: true, message: "Device reset", changes: this.changes });
  });
});

app.post("/api/admin/update-expiration", verifyAdmin, (req, res) => {
  const { email, expiresAt } = req.body;
  db.run("UPDATE users SET expires_at = ? WHERE email = ?", [expiresAt || null, email], function (err) {
    if (err) return res.status(500).json({ success: false, message: "Database error" });
    return res.json({ success: true, message: "Expiration updated", changes: this.changes });
  });
});

// ============================================================
// ELIMINAR USUARIO
// ============================================================
app.delete("/api/admin/delete-user", verifyAdmin, (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ success: false, message: "Email requerido" });
  }
  
  db.run("DELETE FROM users WHERE email = ?", [email], function(err) {
    if (err) {
      console.error("Error al eliminar:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ success: false, message: "Usuario no encontrado" });
    }
    
    return res.json({ success: true, message: "Usuario eliminado" });
  });
});

// ============================================================
// TEST ENDPOINT
// ============================================================
app.get("/test", (req, res) => {
  res.send("SERVER OK");
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () => {
  console.log(`Smart backend running on http://localhost:${PORT}`);
  console.log("Admin login:");
  console.log("Email: admin@smart.local");
  console.log("Password: Admin123456");
});