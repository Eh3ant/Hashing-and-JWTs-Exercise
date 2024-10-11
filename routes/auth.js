/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { SECRET_KEY } = require('../config');
const { ensureLoggedIn } = require('../middleware/auth');

const router = new express.Router();

router.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Missing username or password" });
        }

        const isValid = await User.authenticate(username, password);
        if (!isValid) {
            return res.status(400).json({ error: "Invalid username/password" });
        }

        await User.updateLoginTimestamp(username);

        const token = jwt.sign({ username }, SECRET_KEY);

        return res.json({ token });
    } catch (err) {
        return next(err);
    }
});


router.post('/register', async (req, res, next) => {
    try {
        const { username, password, first_name, last_name, phone } = req.body;

        if (!username || !password || !first_name || !last_name || !phone) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const newUser = await User.register({ username, password, first_name, last_name, phone });

        await User.updateLoginTimestamp(username);

        const token = jwt.sign({ username: newUser.username }, SECRET_KEY);

        return res.status(201).json({ token });
    } catch (err) {
        return next(err);
    }
});

module.exports = router;
