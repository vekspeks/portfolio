const express = require('express');
const router = express.Router();
const db = require('../services/db');
const bcrypt = require('bcrypt');
const Joi = require('joi');


const signupSchema = Joi.object({
  name: Joi.string().min(3).max(100).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  passwordConfirmation: Joi.string().valid(Joi.ref('password')).required()
});


const signinSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});


router.get('/', function (req, res, next) {
  res.send('respond with a resource');
});


router.get('/signup', function (req, res, next) {
  res.render('users/signup');
});


router.post('/signup', async function (req, res, next) {
  const { error } = signupSchema.validate(req.body);
  if (error) {
    return res.render('users/signup', { error_validation: true });
  }


  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`); 
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const query = 'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)';
    await conn.query(query, [req.body.name, req.body.email, hashedPassword]);
    res.render('users/signup', { success: true });
  } catch (error) {
    console.error('Greška pri registraciji:', error);
    res.render('users/signup', { error_database: true });
  } finally {
    if (conn) conn.release();
  }
});


router.get('/signin', function (req, res, next) {
  res.render('users/signin');
});


router.post('/signin', async function (req, res, next) {
  const { error } = signinSchema.validate(req.body);
  if (error) {
    return res.render('users/signin', { error_validation: true });
  }


  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`); // Eksplicitno bira bazu
    const query = 'SELECT password_hash FROM users WHERE email = ?';
    const result = await conn.query(query, [req.body.email]);


    if (result.length === 0) {
      return res.render('users/signin', { unknown_user: true });
    }


    const hashedPasswordDb = result[0].password_hash;
    const compareResult = await bcrypt.compare(req.body.password, hashedPasswordDb);


    if (!compareResult) {
      return res.render('users/signin', { invalid_password: true });
    }


    // Postavljanje kolačića za prijavu
    res.cookie('express-app-user', req.body.email, {
      maxAge: 1209600000, // 14 dana
      httpOnly: true,
      sameSite: 'strict'
    });


    res.redirect('/');
  } catch (error) {
    console.error('Greška pri prijavi:', error);
    res.render('users/signin', { error_database: true });
  } finally {
    if (conn) conn.release();
  }
});


// GET /users/signout - odjava
router.get('/signout', function (req, res, next) {
  res.clearCookie('express-app-user');
  res.redirect('/');
});


module.exports = router;