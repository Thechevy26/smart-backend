require('dotenv').config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(express.static("public"));

// ============================================================
// VARIABLES DE ENTORNO
// ============================================================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Validar variables
if (!JWT_SECRET || !ADMIN_SECRET) {
    console.error("❌ Faltan JWT_SECRET o ADMIN_SECRET en .env");
    process.exit(1);
}

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.error("❌ Faltan ADMIN_EMAIL o ADMIN_PASSWORD en .env");
    process.exit(1);
}

console.log("✅ Variables de entorno cargadas correctamente");

// ============================================================
// CONEXIÓN A POSTGRESQL (RAILWAY)
// ============================================================
const db = new Pool({
  connectionString: "postgresql://postgres:dxzttxOcyOwyYUDPJjsodibGoMFHVqeY@postgres.railway.internal:5432/railway",
});

// ============================================================
// RATE LIMITING
// ============================================================
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: "Demasiados intentos. Espera 15 minutos." },
    skipSuccessfulRequests: true
});

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
async function initDb() {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                can_use_app INTEGER DEFAULT 1,
                device_id TEXT,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        `);

        const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
        await db.query(
            `INSERT INTO admins (email, password_hash, role) VALUES ($1, $2, 'admin') ON CONFLICT (email) DO NOTHING`,
            [ADMIN_EMAIL, adminHash]
        );

        console.log("✅ Base de datos inicializada");
    } catch (err) {
        console.error("❌ Error inicializando DB:", err);
        process.exit(1);
    }
}

initDb();

// ============================================================
// MIDDLEWARES
// ============================================================
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    if (!token) return res.status(401).json({ success: false, message: "Missing token" });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ success: false, message: "Invalid or expired token" });
    }
}

function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    if (!token) return res.status(401).json({ success: false, message: "Missing admin token" });
    try {
        req.admin = jwt.verify(token, ADMIN_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ success: false, message: "Invalid admin token" });
    }
}

// ============================================================
// ENDPOINTS PARA APP ANDROID
// ============================================================

app.post("/api/auth/login", async (req, res) => {
    const { email, password, deviceId } = req.body;
    if (!email || !password || !deviceId) {
        return res.status(400).json({ success: false, message: "email, password and deviceId are required" });
    }

    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
        if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ success: false, message: "Invalid credentials" });
        if (user.active !== 1 || user.can_use_app !== 1) return res.status(403).json({ success: false, message: "User not allowed" });

        const today = new Date();
        const expiresAt = user.expires_at ? new Date(user.expires_at) : null;
        if (expiresAt && expiresAt < today) return res.status(403).json({ success: false, message: "License expired" });

        if (!user.device_id) {
            await db.query("UPDATE users SET device_id = $1 WHERE id = $2", [deviceId, user.id]);
        } else if (user.device_id !== deviceId) {
            return res.status(403).json({ success: false, message: "This account is already linked to another device" });
        }

        await db.query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [user.id]);

        const token = jwt.sign({ userId: user.id, email: user.email, deviceId }, JWT_SECRET, { expiresIn: "30d" });
        const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt.getTime() - today.getTime()) / 1000)) : 0;

        res.json({
            success: true, token, expiresAt: user.expires_at, secondsRemaining,
            displayRemaining: formatRemaining(secondsRemaining * 1000),
            user: { email: user.email, active: user.active === 1, canUseApp: user.can_use_app === 1 }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.get("/api/auth/session-status", verifyToken, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [req.user.userId]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        const now = Date.now();
        const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
        const isExpired = expiresAt && expiresAt < now;
        const isBlocked = user.can_use_app !== 1 || user.active !== 1;
        const deviceValid = !user.device_id || user.device_id === req.user.deviceId;
        const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;

        res.json({
            success: true, allowed: !isExpired && !isBlocked && deviceValid,
            expired: isExpired, blocked: isBlocked, deviceValid,
            expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
            secondsRemaining, displayRemaining: formatRemaining(secondsRemaining * 1000)
        });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post("/api/auth/can-activate", verifyToken, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [req.user.userId]);
        const user = result.rows[0];
        if (!user) return res.json({ canActivate: false, message: "User not found" });

        const now = Date.now();
        const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
        const isExpired = expiresAt && expiresAt < now;
        const isBlocked = user.can_use_app !== 1 || user.active !== 1;
        const deviceValid = !user.device_id || user.device_id === req.user.deviceId;
        const canActivate = !isExpired && !isBlocked && deviceValid;
        const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;

        let message = "OK";
        if (isExpired) message = "License expired";
        else if (isBlocked) message = "User blocked";
        else if (!deviceValid) message = "Account linked to another device";

        res.json({ canActivate, expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
            secondsRemaining, displayRemaining: formatRemaining(secondsRemaining * 1000), message });
    } catch (err) {
        res.json({ canActivate: false, message: "Error" });
    }
});

app.get("/api/auth/validate", verifyToken, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [req.user.userId]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ valid: false, message: "User not found" });

        const now = Date.now();
        const expiresAt = user.expires_at ? new Date(user.expires_at).getTime() : null;
        const isExpired = expiresAt && expiresAt < now;
        const isBlocked = user.can_use_app !== 1 || user.active !== 1;
        const deviceValid = !user.device_id || user.device_id === req.user.deviceId;

        if (isExpired || isBlocked || !deviceValid) {
            return res.status(401).json({ valid: false, message: isExpired ? "License expired" : (isBlocked ? "User blocked" : "Invalid device") });
        }

        const secondsRemaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;
        res.json({ valid: true, expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
            secondsRemaining, displayRemaining: formatRemaining(secondsRemaining * 1000) });
    } catch (err) {
        res.status(401).json({ valid: false });
    }
});

// ============================================================
// ENDPOINTS DE ADMIN
// ============================================================

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await db.query("SELECT * FROM admins WHERE email = $1", [email]);
        const admin = result.rows[0];
        if (!admin) return res.status(401).json({ success: false, message: "Invalid admin credentials" });
        if (!bcrypt.compareSync(password, admin.password_hash)) return res.status(401).json({ success: false, message: "Invalid admin credentials" });
        const token = jwt.sign({ adminId: admin.id, email: admin.email, role: admin.role }, ADMIN_SECRET, { expiresIn: "12h" });
        res.json({ success: true, token, admin: { email: admin.email, role: admin.role } });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post("/api/admin/create-user", verifyAdmin, async (req, res) => {
    const { email, password, expiresAt } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "email and password are required" });
    const hash = bcrypt.hashSync(password, 10);
    try {
        await db.query(
            `INSERT INTO users (email, password_hash, active, can_use_app, expires_at) VALUES ($1, $2, 1, 1, $3)`,
            [email, hash, expiresAt || null]
        );
        res.json({ success: true, message: "User created" });
    } catch (err) {
        res.status(400).json({ success: false, message: "User already exists or invalid data" });
    }
});

app.get("/api/admin/users", verifyAdmin, async (req, res) => {
    const result = await db.query(`SELECT id, email, active, can_use_app, device_id, expires_at, created_at, last_login FROM users ORDER BY id DESC`);
    res.json({ success: true, users: result.rows });
});

app.post("/api/admin/block-user", verifyAdmin, async (req, res) => {
    await db.query("UPDATE users SET active = 0, can_use_app = 0 WHERE email = $1", [req.body.email]);
    res.json({ success: true, message: "User blocked" });
});

app.post("/api/admin/activate-user", verifyAdmin, async (req, res) => {
    await db.query("UPDATE users SET active = 1, can_use_app = 1 WHERE email = $1", [req.body.email]);
    res.json({ success: true, message: "User activated" });
});

app.post("/api/admin/reset-device", verifyAdmin, async (req, res) => {
    await db.query("UPDATE users SET device_id = NULL WHERE email = $1", [req.body.email]);
    res.json({ success: true, message: "Device reset" });
});

app.post("/api/admin/update-expiration", verifyAdmin, async (req, res) => {
    await db.query("UPDATE users SET expires_at = $1 WHERE email = $2", [req.body.expiresAt || null, req.body.email]);
    res.json({ success: true, message: "Expiration updated" });
});

app.delete("/api/admin/delete-user", verifyAdmin, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email requerido" });
    const result = await db.query("DELETE FROM users WHERE email = $1", [email]);
    if (result.rowCount === 0) return res.status(404).json({ success: false, message: "Usuario no encontrado" });
    res.json({ success: true, message: "Usuario eliminado" });
});

// ============================================================
// TEST ENDPOINT
// ============================================================
app.get("/test", (req, res) => {
    res.send("SERVER OK");
});

// ============================================================
// RUTA OCULTA PARA PANEL ADMIN
// ============================================================
app.get("/sda-control-panel", (req, res) => {
    res.sendFile(__dirname + "/public/admin.html");
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () => {
    console.log(`✅ Smart backend running on http://localhost:${PORT}`);
    console.log("📊 Panel Admin: http://localhost:" + PORT + "/sda-control-panel");
    console.log("🔐 Admin login con credenciales del .env");
});
