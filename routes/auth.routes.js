const express = require('express');
const router = express.Router();

// Require user model
const User = require("../models/User.model");

// Add bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;

// Add passport
const passport = require("passport");


const ensureLogin = require('connect-ensure-login');


//Get & Post Signup
router.get("/signup", (req, res, next) => {
  res.render("views/auth/singup.hbs");
});

router.post("/signup", (req, res, next) => {
  let { username, password } = req.body;

  //check if fields are empty
  if (username === "" || password === "") {
    res.render("views/auth/singup", {
      message: "Please, don't forget to insert your credentials :)"
    });
    return;
  }

  //check if username is valid 
  User.findOne({ username })
  .then(user => {
    if (user !== null) {
      res.render("views/auth/singup", {
        message: "These username is already taken, please choose other"
      });
      return
    }

    //bcrypt for password security - from bcrypt doc
    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    //Create user:
    const newUser = new User({
      username,
      password: hashPass
    });

    newUser.save(err => {
      if (err) {
        res.render("views/auth/singup", { message: "Something is not right"});
      } else {
        res.redirect("views/auth/login");
      }
    });
  })
  .catch(err => {
    next(err);
  });
});



//Get & Post Login
router.get("/login", (req, res, next) => {
  res.render("views/auth/login", { message: req.flash("error") });
});

    //Start session with Passport
router.post("/login", (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
    passReqToCallback: true
  })(req, res, next);
});



// Get a private page
router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("views/auth/private", { user: req.user });
});


//Get Logout
router.get("/logout", (req, res, next) => {
  req.logout();
  res.redirect("/");
});

module.exports = router;
