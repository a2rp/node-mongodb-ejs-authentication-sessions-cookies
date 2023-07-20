require("dotenv").config();

const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const MongoDBSession = require("connect-mongodb-session")(session);
let bcrypt = require("bcrypt");
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

const UserModel = require("./api/models/User.model");
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    // useCreateIndex: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('MongoDB connection established.');
}).catch((error) => {
    console.error("MongoDB connection failed:", error.message);
});

const store = new MongoDBSession({
    uri: MONGODB_URI,
    collection: "mySessions"
});

app.use(session({
    secret: "a2rp", // key to sign the cookie
    resave: false,
    saveUninitialized: false,
    store
}));

const isAuth = (req, res, next) => {
    if (req.session && req.session.isAuth) {
        next();
    } else {
        res.redirect("/login");
    }
};

app.get("/a2rp", (req, res) => {
    res.json({
        status: true,
        message: "a2rp: an Ashish Ranjan presentation"
    });
});

app.get("/test", (req, res) => {
    req.session.isAuth = true;
    console.log(req.session);
    console.log(req.session.id);
    res.json({
        status: true,
        message: "root route"
    });
});

app.get("/", (req, res) => {
    res.render("landing");
});

app.get("/login", (req, res) => {
    if (req.session.isAuth) {
        return res.render("dashboard", { message: req.session.user });
    }
    res.render("login");
});

app.post("/login", async (req, res) => {
    const { usernameEmail, password } = req.body;
    const user = await UserModel.findOne({ $or: [{ username: usernameEmail }, { email: usernameEmail }] });
    if (!user) {
        return res.render("login", { message: "Username or email not found." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.redirect("login", { message: "Password is incorrect." });
    }

    req.session.user = usernameEmail;
    req.session.isAuth = true;
    res.redirect("dashboard");
});

app.get("/register", (req, res) => {
    if (req.session.isAuth) {
        return res.render("dashboard", { message: req.session.user });
    }
    res.render("register");
});

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    let user = await UserModel.findOne({ email });
    if (user) {
        return res.redirect("/register");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new UserModel({
        username, email, password: hashedPassword
    });
    await user.save();
    res.redirect("/login");
});

app.get("/dashboard", isAuth, (req, res) => {
    res.render("dashboard", { message: req.session.user });
});

app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            throw err;
        }
        res.redirect("/");
    });
});

const PORT = process.env.PORT || 1198;
app.listen(PORT, console.log(`server running on port ${PORT}`));

