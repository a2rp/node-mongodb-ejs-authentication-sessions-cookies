require("dotenv").config();

const { randomBytes } = require("node:crypto");
const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const MongoDBStore = require("connect-mongodb-session")(session);
const { rateLimit } = require("express-rate-limit");
const UserModel = require("./api/models/User.model");

const app = express();
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SESSION_MAX_AGE = 8 * 60 * 60 * 1000;
const SESSION_COOKIE_NAME = "a2rp.sid";
const BCRYPT_ROUNDS = 12;
const MAX_PASSWORD_BYTES = 72;
const cookieSecure = process.env.NODE_ENV === "production";
const dummyPasswordHash = bcrypt.hash("authentication-demo-dummy-password", BCRYPT_ROUNDS);

app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false, limit: "16kb", parameterLimit: 10 }));

let sessionStore = null;
let sessionStoreReady = Promise.resolve();
if (MONGODB_URI) {
    sessionStoreReady = new Promise((resolve, reject) => {
        sessionStore = new MongoDBStore({
            uri: MONGODB_URI,
            databaseName: process.env.MONGODB_DATABASE || undefined,
            collection: "sessions",
            expires: SESSION_MAX_AGE,
            connectionOptions: { serverSelectionTimeoutMS: 10000 }
        }, (error) => error ? reject(error) : resolve());

        sessionStore.on("error", (error) => {
            console.error("Session store error:", error.name);
        });
    });
    // The startup routine awaits this promise; attaching a handler here also
    // prevents an early connection failure from becoming an unhandled rejection.
    sessionStoreReady.catch(() => {});
}

app.use(session({
    name: SESSION_COOKIE_NAME,
    secret: SESSION_SECRET || randomBytes(32).toString("hex"),
    store: sessionStore || undefined,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: cookieSecure,
        maxAge: SESSION_MAX_AGE
    }
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler(req, res) {
        const view = req.path === "/login" ? "login" : "register";
        return res.status(429).render(view, { message: "Too many attempts. Please try again later." });
    }
});

function asyncRoute(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((error) => error ? reject(error) : resolve());
    });
}

function destroySession(req) {
    return new Promise((resolve, reject) => {
        req.session.destroy((error) => error ? reject(error) : resolve());
    });
}

function isAuthenticated(req, res, next) {
    if (req.session && typeof req.session.userId === "string") return next();
    return res.redirect("/login");
}

function normalizeCredentials(body) {
    if (!body || typeof body !== "object" || Array.isArray(body)) return {};

    return {
        username: typeof body.username === "string" ? body.username.trim().toLowerCase() : "",
        email: typeof body.email === "string" ? body.email.trim().toLowerCase() : "",
        usernameEmail: typeof body.usernameEmail === "string" ? body.usernameEmail.trim().toLowerCase() : "",
        password: typeof body.password === "string" ? body.password : ""
    };
}

function validEmail(email) {
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get("/a2rp", (_req, res) => {
    res.json({ status: true, message: "a2rp: an Ashish Ranjan presentation" });
});

app.get("/", (_req, res) => res.render("landing"));

app.get("/login", (req, res) => {
    if (req.session.userId) return res.redirect("/dashboard");
    return res.render("login");
});

app.post("/login", authLimiter, asyncRoute(async (req, res) => {
    const { usernameEmail, password } = normalizeCredentials(req.body);
    if (!usernameEmail || !password) {
        return res.status(400).render("login", { message: "Enter your username/email and password." });
    }
    if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
        return res.status(401).render("login", { message: "Invalid username/email or password." });
    }

    const user = await UserModel.findOne({
        $or: [{ username: usernameEmail }, { email: usernameEmail }]
    }).select("+password").exec();

    const passwordHash = user ? user.password : await dummyPasswordHash;
    const passwordMatches = await bcrypt.compare(password, passwordHash);
    if (!user || !passwordMatches) {
        return res.status(401).render("login", { message: "Invalid username/email or password." });
    }

    await regenerateSession(req);
    req.session.userId = user._id.toString();
    req.session.username = user.username;
    return res.redirect("/dashboard");
}));

app.get("/register", (req, res) => {
    if (req.session.userId) return res.redirect("/dashboard");
    return res.render("register");
});

app.post("/register", authLimiter, asyncRoute(async (req, res) => {
    const { username, email, password } = normalizeCredentials(req.body);
    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) {
        return res.status(400).render("register", { message: "Username must be 3-32 letters, numbers, dots, underscores, or hyphens." });
    }
    if (!validEmail(email)) {
        return res.status(400).render("register", { message: "Enter a valid email address." });
    }
    if (password.length < 8 || Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
        return res.status(400).render("register", { message: "Password must be at least 8 characters and at most 72 UTF-8 bytes." });
    }

    try {
        const existingUser = await UserModel.exists({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(409).render("register", { message: "That username or email is already registered." });
        }

        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        await UserModel.create({ username, email, password: passwordHash });
        return res.redirect("/login");
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).render("register", { message: "That username or email is already registered." });
        }
        throw error;
    }
}));

app.get("/dashboard", isAuthenticated, (req, res) => {
    res.render("dashboard", { message: req.session.username });
});

app.post("/logout", asyncRoute(async (req, res) => {
    await destroySession(req);
    res.clearCookie(SESSION_COOKIE_NAME, {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure: cookieSecure
    });
    return res.redirect("/");
}));

app.use((_req, res) => res.status(404).render("landing", { message: "Page not found." }));

app.use((error, _req, res, _next) => {
    if (error.type === "entity.too.large") {
        return res.status(413).render("login", { message: "Form submission is too large." });
    }

    console.error("Request failed:", error.name, error.code || "");
    return res.status(500).render("login", { message: "An unexpected error occurred. Please try again." });
});

async function startServer() {
    if (!MONGODB_URI) throw Object.assign(new Error("MONGODB_URI is required."), { code: "CONFIGURATION_ERROR" });
    if (!SESSION_SECRET || Buffer.byteLength(SESSION_SECRET, "utf8") < 32) {
        throw Object.assign(new Error("SESSION_SECRET must contain at least 32 bytes."), { code: "CONFIGURATION_ERROR" });
    }

    const port = Number(process.env.PORT || 1198);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw Object.assign(new Error("PORT must be an integer between 1 and 65535."), { code: "CONFIGURATION_ERROR" });
    }

    const host = process.env.HOST || "127.0.0.1";
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    await Promise.all([sessionStoreReady, UserModel.init()]);
    mongoose.connection.on("error", (error) => console.error("MongoDB connection error:", error.name));
    app.listen(port, host, () => console.log(`Authentication demo listening at http://${host}:${port}`));
}

if (require.main === module) {
    startServer().catch(async (error) => {
        if (error.code === "CONFIGURATION_ERROR") {
            console.error(error.message);
        } else {
            console.error("Could not start authentication demo:", error.name);
        }
        await mongoose.disconnect().catch(() => {});
        if (sessionStore && sessionStore.client) await sessionStore.client.close().catch(() => {});
        process.exitCode = 1;
    });
}

module.exports = app;
