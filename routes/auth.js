const express = require('express');
const validator= require('express-validator');
const { body } = require('express-validator');


const authController = require('../controllers/auth');
const User = require('../models/user');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login', [
    validator.body('email')
    .isEmail()
    .withMessage('Please enter a valid email address.')
    .normalizeEmail(),
    validator.body('password','Password has to be valid.')
    .isLength({min: 5})
    .isAlphanumeric()
    .trim()

],
 authController.postLogin);

//router.post('/signup', validator.check('email').isEmail(), authController.postSignup);
router.post(
    '/signup',
    [
    validator.check('email')
      .isEmail()
      .withMessage('Please enter a valid email.')
      .custom((value, { req }) => {
        return User.findOne({ email: value }).then(userDoc => {
            if (userDoc) {
              return Promise.reject(
                'E-Mail exists already, please pick a different one.'
              );
            }
          });
        })
        .normalizeEmail(),
      validator.body(
        'password',
        'Please enter a password with only numbers and text and at least 5 characters.'
      )
      .isLength({min: 5})
      .isAlphanumeric()
      .trim(),
      validator.body('confirmPassword').trim().custom((value, {req}) => {
        if(value !== req.body.password){
            throw new Error('Passwords have to match');
        }
        return true;
      })
    ],
    authController.postSignup
  );

router.post('/logout', authController.postLogout);

router.get('/user/verify', authController.verifyMail);

module.exports = router;

