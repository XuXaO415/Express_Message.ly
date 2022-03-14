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

router.post('/login', async(req, res, next) => {

        try {
            const { username, password } = req.body;
            if (!username || !password) {
                throw new ExpressError("Username and password required", 400);
            }
            const results = await db.query(`SELECT username, password FROM users WHERE username = $1`, [username]);
            const user = results.rows[0];
            if (user) {
                if (await bcrypt.compare(password, user.password)) {
                    const token = jwt.sign({ username }, SECRET_KEY);
                    return res.json({ message: `Logged in`, token })
                }
            }
            throw new ExpressError("Invalid username/password", 400);
        } catch (e) {
            return next(e);
        }
    })
    // router.post("/login", async(req, res, next) => {
    //     try {
    //         const { username, password } = req.body;
    //         if (!username || !password) {
    //             throw new ExpressError("Username and password required", 400);
    //         }

//         const authUser = await User.authenticate(username, password);
//         if (!authUser) {
//             if (bcrypt.compare(password, authUser.password)) {
//                 throw new ExpressError("Invalid user", 400);
//             }
//         }
//         User.updateLoginTimestamp(username);
//         const token = jwt.sign({ username }, SECRET_KEY);
//         return res.json({ message: `Logged in ${username}`, token })
//     } catch (e) {
//         return next(e);
//     }
// });



/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async(req, res, next) => {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if (!username || !password || !first_name || !last_name || !phone) {
            throw new ExpressError("Your full credentials are needed", 400);
        }
        // Hashes password
        const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
        const results = await db.query(`INSERT INTO users (username, password)
        VALUES ($1, $2) 
        RETURNING username`, [username, hashedPassword]);
        return res.json(results.rows[0]);

    } catch (e) {
        if (e.code === '23505') {
            return next(new ExpressError("Username taken. Please pick another!", 400));
        }
        return next(e)
    }
});

module.exports = router;