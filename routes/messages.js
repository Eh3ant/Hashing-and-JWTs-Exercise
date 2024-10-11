const express = require('express');
const Message = require('../models/message');
const { ensureLoggedIn, ensureCorrectUser } = require('../middleware/auth');
const ExpressError = require('../expressError');

const router = new express.Router();


router.get('/:id', ensureLoggedIn, async (req, res, next) => {
    try {
        const message = await Message.get(req.params.id);


        if (
            req.user.username !== message.from_user.username &&
            req.user.username !== message.to_user.username
        ) {
            throw new ExpressError('Unauthorized', 401);
        }

        return res.json({ message });
    } catch (err) {
        return next(err);
    }
});


router.post('/', ensureLoggedIn, async (req, res, next) => {
    try {
        const { to_username, body } = req.body;


        const message = await Message.create({
            from_username: req.user.username,
            to_username,
            body,
        });

        return res.status(201).json({ message });
    } catch (err) {
        return next(err);
    }
});


router.post('/:id/read', ensureLoggedIn, async (req, res, next) => {
    try {
        const message = await Message.get(req.params.id);


        if (message.to_user.username !== req.user.username) {
            throw new ExpressError('Unauthorized', 401);
        }

        const updatedMessage = await Message.markRead(req.params.id);

        return res.json({ message: updatedMessage });
    } catch (err) {
        return next(err);
    }
});

module.exports = router;
















/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

