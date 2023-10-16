const router = require("express").Router()
const User = require("../models/User");
const passport = require("passport");

// const _ = require("lodash");
const bcrypt = require("bcrypt");

//routes

// Set up Google OAuth routes
router.get("/auth/google",
    passport.authenticate("google", { scope: ['https://www.googleapis.com/auth/plus.login'] })
);
router.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
        return res.redirect("/secrets");
    }
);

router.get("/",function (req, res) {
        res.render("home");
    });

router.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    .post(async function (req, res) {
        const { username, password } = req.body;

        const user = await User.findOne({ username })
        if (!user) {
            return res.redirect("/login");
        }
        else {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                req.logIn(user, (err) => {
                    if (err) {
                        console.error(err);
                        return res.redirect("/login");
                    } else {
                        return res.redirect("/secrets");
                    }
                });
            } else {
                return res.redirect("/login");
            }
        }
    });


router.route('/register')
    .get((req, res) => {
        res.render('register');
    })
    .post(async (req, res) => {
        try {
            const { username, password } = req.body;

            const existingUser = await User.findOne({ username });

            if (existingUser) {
                return res.redirect('/register');
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = new User({ username, password: hashedPassword });
            await newUser.save();

            req.logIn(newUser, (err) => {
                if (err) {
                    console.error(err);
                    return res.redirect('/login');
                }
                return res.redirect('/secrets');
            });
        } catch (error) {
            console.error(error);
            return res.redirect('/register');
        }
    });

router.route("/secrets")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            User.find({ secret: { $ne: null } })
                .then((users) => {
                    return res.render("secrets", { users: users });
                })

        } else {
            return res.redirect("/");
        }
    });

router.get("/logout", function (req, res) {
    req.logout(() => {
        res.redirect("/");
    });
});
router.route("/submit")
    .get((req, res) => {
        res.render("submit");
    })
router.post("/submit",async (req, res) => {
        if (req.isAuthenticated()) {
            try {
                const user = await User.findById(req.user._id);
                if (!user) {
                    return res.redirect("/submit"); 
                }
                user.secret = req.body.secret;
                await user.save();

                res.redirect("/secrets");
            } catch (error) {
                console.error(error);
                res.redirect("/submit"); 
            }
        } else {
            res.redirect("/login"); 
        }
    });


module.exports = router;