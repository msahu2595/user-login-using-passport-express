const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const passport = require('passport');

//user model
const User = require("../models/User")


//login page
router.get("/login", (req, res) => res.render('login'));


//register page
router.get("/register", (req, res) => res.render('register'));

//register users
router.post("/register", (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];
    
    //check error
    if(!name || !email || !password || !password2) {
        errors.push({msg: "Please fill all fields."})
    }

    //check password
    if(password !== password2) {
        errors.push({msg: "Password do not match."})
    }

    //check password length
    if(password.length < 6) {
        errors.push({msg: "Password length should be atleast 6."})
    }
    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        //validation passes
        User.findOne({ email: email})
            .then(user => {
                if(user) {
                    //user exists
                    errors.push({ msg: "Email is already registered" });
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else { 
                    const newUser = new  User({
                        name,
                        email,
                        password
                    });
                    //hash password
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if(err) throw err;
                            //set password to hash
                            newUser.password = hash;
                            // save user
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now Registered')
                                    res.redirect("/users/login");
                                })
                                .catch(err => console.log(err));
                        })
                    })
                }
            });
    }
});


//login handle
router.post('/login', (req, res, next) => {
    passport.authenticate("local",{
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next)
})

//logout handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash("success_msg", "You have successfullly logout"); 
    res.redirect('/users/login');
});

module.exports = router; 