const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User model
const User = require('../models/User');

// Login Page
router.get('/login', function(req,res){
    res.render('login');
});

// register Page
router.get('/register', function(req,res){
    res.render('register');
});

// register handle
router.post('/register', function(req,res){
    // console.log(req.body);
    // res.send('hello');

    // Pull data out of req.body
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Check required fields
    if(!name || !email || !password || !password2){
        errors.push({ msg: 'Please fill in all fields'});
    }

    // Check passwords match
    if(password !== password2){
        errors.push({msg: 'Passwords do not match'});
    }

    // Check passwords length
    if(password.length < 6){
        errors.push({msg: 'Passwords length must be at least 6 characters'});
    }

    if(errors.length > 0){
        res.render('register',{
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation passed
        User.findOne({ email: email })
            .then(user => {
                if(user){
                    // User exists
                    errors.push({ msg: 'Email is already registered' });
                    res.render('register',{
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {

                    // the below syntax is ES6
                    // the meaning of name here is name: name 

                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    // Hash Password
                    bcrypt.genSalt(10, function(err,salt){
                        bcrypt.hash(newUser.password, salt, function(err,hash){
                            if(err) throw err;
                            // Set password to hashed
                            newUser.password = hash;
                            // Save User
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered and can log in');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                        })
                    })
                }
            });
    }

});

// Login Handle
router.post('/login', (req,res,next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req,res,next);
});

// Logout Handle 
router.get('/logout', (req,res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
})

module.exports = router;