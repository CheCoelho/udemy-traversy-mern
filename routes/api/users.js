const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');           //removed '/check' based on deprication warning, which was not indicated in the tutorial.

const User = require('../../models/User');



/// @route      POST api/users
//  @desc       Register User
//  @access     Public
router.post('/', [
    check('name', 'Name is required')
    .not()                                                                          //check that name is not empty
    .isEmpty(), 
    check('email', 'Please include a valid email').isEmail(),                       //check that email is valid
    check('password', 'Please enter a password with 6 or more characters')
    .isLength({ min: 6 })                                                           //check password is 6 or more characters
    ], 
    async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body

        try{
            let user = await User.findOne({ email });

            if(user) {
                return res.status(400).json({ errors: [ { ms: 'User with that email already exists' } ] });                                                 //check if user exists to avoid to users with same email address
            }
            
            //Get avatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })

            //Create user (doesn't save)
            user = new User({
                name,
                email,
                avatar,
                password
            });

            //Hash password with salt, 10 rounds
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(payload, 
                config.get('jwtSecret'),
                    { expiresIn: 360000 },
                    (err, token) => {
                    if (err) throw err;
                    res.json({ token })
                    }
                );

        } catch(err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }

    });


module.exports = router;
