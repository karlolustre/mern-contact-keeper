const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('../middleware/auth');
const { check, validationResult } = require('express-validator/check');

const User = require('../models/User');

//@route GET api/auth
//@desc get logged in user
//@access Private
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

//@route POST api/auth
//@desc Auth user & get token, this is login
//@access Public
router.post('/', [
    check('email', 'Please enter your email').isEmail(),
    check('password', 'Please enter your password').exists(),
    check('name', 'Please enter your name').exists()
], async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;

    try {
        let user = await User.findOne({email});

        if(!user) {
            return res.status(422).json({ msg: 'Invalid Credentials' });
        }

        const userName = await name;
        // console.log(userName)
        if(userName !== user.name) {
            return res.status(422).json({ msg: 'please check your name '});
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) {
            return res.status(422).json({ msg: 'Invalid Credentials' });
        }

        const payload = {
            user: {
                id: user.id
            }
        }
    
        jwt.sign(payload, config.get('jwtSecret'), {
            expiresIn: 360000 
        }, (err, token) => {
            if (err) throw err;
            res.json({ token });    
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;
