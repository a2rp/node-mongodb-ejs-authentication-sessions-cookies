const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        minlength: 3,
        maxlength: 32,
        match: /^[a-z0-9][a-z0-9._-]{2,31}$/,
        unique: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        maxlength: 254,
        match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        unique: true
    },
    password: {
        type: String,
        required: true,
        select: false
    }
}, {
    timestamps: true,
    versionKey: false
});

module.exports = mongoose.model("User", userSchema);
