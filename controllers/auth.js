const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const  validator  = require('express-validator');
const { validationResult } = require('express-validator');
const dotenv = require('dotenv').config();

const User = require('../models/user');
const { func } = require('joi');

const sendVerifyMail = async(email,user) => {
  try{
    const transporter = nodemailer.createTransport({
      host:'smtp.gmail.com',
      port:587,
      secure:false,
      requireTLS:true,
      auth:{
        user:'0923riteshkumar@gmail.com',
        pass: `${process.env.PASS_KEY}`
      }
    });
    const mailOptions = {
      from:'0923riteshkumar@gmail.com',
      to: email,
      subject:'Verification Mail',
      html:'<p> Hii, please click here to <a href="http://localhost:4000/user/verify?id='+user+'"> Verify </a> your mail. </p>'
    }

    transporter.sendMail(mailOptions,function(error,info){
      if(error){
        console.log(error);
      }else{
        console.log("Email has been sent:-", info.response);
      }
    })
  } catch(error){
    console.log(error.message);
  }
}

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
        email: '',
        password: ''
      },
      validationErrors: []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
        email: '',
        password: '',
        confirmPassword: ''
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;

    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email: email,
                password: password
              },
              validationErrors: errors.array()
          });
    }

    User.findOne({ email: email })
      .then(user => {
        if (!user) {
          req.flash('error', 'Invalid email or password.');
          return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: 'Invalid email or password.',
            oldInput: {
                email: email,
                password: password
              },
              validationErrors: []
          });
        }
        bcrypt
          .compare(password, user.password)
          .then(doMatch => {
            if (doMatch) {
              req.session.isLoggedIn = true;
              req.session.user = user;
              return req.session.save(err => {
                console.log(err);
                res.redirect('/');
              });
            }
            return res.status(422).render('auth/login', {
                path: '/login',
                pageTitle: 'Login',
                errorMessage: 'Invalid email or password.',
                oldInput: {
                    email: email,
                    password: password
                  },
                  validationErrors: []
              });
          })
          .catch(err => {
            console.log(err);
            res.redirect('/login');
          });
      })
      .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      });
  };

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  
  const errors = validator.validationResult(req);

  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
      validationErrors: errors.array(),
    });
  }
  
  bcrypt
    .hash(password, 12)
    .then(hashedPassword => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] },
      });

      user
        .save()
        .then(result => {
          res.redirect('/login');
          sendVerifyMail(req.body.email, user._id);
        })
        .catch(err => {
          const error = new Error(err);
          error.httpStatusCode = 500;
          return next(error);
        });
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.verifyMail = async (req, res) => {
  try {
    const updateInfo = await User.updateOne({ _id: req.query.id }, { $set: { isVerified: 1 } });
    console.log(updateInfo);
    res.render("auth/email-verified");
  } catch (error) {
    console.log(error.message);
  }
};

