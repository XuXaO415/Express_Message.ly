const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const { authenticateJWT, ensureLoggedIn, ensureCorrectUser } = require('../middleware/auth');
const User = require("../models/user")

router.get('/', (req, res, next) => {
        res.send("I WORK, YAY!")
    })
    // router.post("/login", async(rew, res, next) => {
    //     try {
    //         const { username, password } = req.body;
    //         //hash password
    //         const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    //         // save to db
    //         const results = await db.query(
    //             `INSERT INTO users (username, password)
    //         VALUES($1, $2)
    //         RETURNING username`, [username, hashedPassword]
    //         );
    //         return res.json(results.rows[0]);
    //     } catch (e) {
    //         return next(e);
    //     }
    // });
    // router.post("/login", async(req, res, next) => {
    //     try {
    //         const { username, password } = req.body;
    //         if (!username || !password) {
    //             throw new ExpressError("Username and password required", 400);
    //         }
    //         const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    //         const results = await db.query(
    //             `INSERT INTO users (username, password)
    //             VALUES($1, $2)
    //             RETURNING username`, [username, hashedPassword]
    //         );
    //         return res.json(results.rows[0]);
    //     } catch (e) {
    //         return next(e);
    //     }
    // });


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async(req, res, next) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            throw new ExpressError("Username and password required", 400);
        }

        const results = await db.query(
            `SELECT username, password
            FROM users WHERE username = $1`, [username]);
        const user = results.rows[0];
        if (user) {
            if (bcrypt.compare(password, user.password)) {
                return res.json({
                    message: `Logged in!`
                })
            }
        }
        throw new ExpressError("Username not found", 404);
    } catch (e) {
        return next(e);
    }
});



/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

module.exports = router;