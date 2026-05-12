require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;

async function connectDB() {
  const client = new MongoClient(mongoUrl);
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection('users');
  console.log('Connected to MongoDB');
}

connectDB().catch(console.error);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUrl,
    dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions',
    crypto: { secret: process.env.MONGODB_SESSION_SECRET },
    ttl: 3600 // 1 hour
  }),
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

function isLoggedIn(req) {
  return req.session && req.session.authenticated;
}

function isAdmin(req) {
  return isLoggedIn(req) && req.session.user_type === 'admin';
}

// GET /
app.get('/', (req, res) => {
  res.render('index', {
    title: 'Home',
    user: isLoggedIn(req) ? req.session.name : null,
    isAdmin: isAdmin(req)
  });
});

// GET /signup
app.get('/signup', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/members');
  res.render('signup', { title: 'Sign Up', user: null, isAdmin: false });
});

// POST /signupSubmit
app.post('/signupSubmit', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) return res.render('signup', { title: 'Sign Up', user: null, isAdmin: false, error: 'Name is required.' });
  if (!email) return res.render('signup', { title: 'Sign Up', user: null, isAdmin: false, error: 'Please provide an email address.' });
  if (!password) return res.render('signup', { title: 'Sign Up', user: null, isAdmin: false, error: 'Password is required.' });

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    return res.render('signup', { title: 'Sign Up', user: null, isAdmin: false, error: validationResult.error.details[0].message });
  }

  try {
    const existing = await userCollection.findOne({ email });
    if (existing) return res.render('signup', { title: 'Sign Up', user: null, isAdmin: false, error: 'Email already exists.' });

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = 'user';
    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.render('signup', { title: 'Sign Up', user: null, isAdmin: false, error: 'Server error. Please try again.' });
  }
});

// GET /login
app.get('/login', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/members');
  res.render('login', { title: 'Log In', user: null, isAdmin: false });
});

// POST /loginSubmit
app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    return res.render('login', { title: 'Log In', user: null, isAdmin: false, error: 'Invalid input.' });
  }

  try {
    const user = await userCollection.findOne({ email });
    if (!user) return res.render('login', { title: 'Log In', user: null, isAdmin: false, error: 'Invalid email/password combination.' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.render('login', { title: 'Log In', user: null, isAdmin: false, error: 'Invalid email/password combination.' });

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type || 'user';
    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.render('login', { title: 'Log In', user: null, isAdmin: false, error: 'Server error. Please try again.' });
  }
});

// GET /members
app.get('/members', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');
  res.render('members', {
    title: 'Members Area',
    name: req.session.name,
    user: req.session.name,
    isAdmin: isAdmin(req)
  });
});

// GET /admin
app.get('/admin', async (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/login');
  if (!isAdmin(req)) {
    return res.status(403).render('404', {
      title: 'Access Denied',
      user: req.session.name,
      isAdmin: false,
      error: 'You are not authorized to view this page.'
    });
  }

  try {
    const users = await userCollection.find().toArray();
    res.render('admin', {
      title: 'Admin Panel',
      users,
      user: req.session.name,
      isAdmin: true
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
  }
});

// GET /admin/promote
app.get('/admin/promote', async (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');

  const schema = Joi.string().email().max(100).required();
  const { error } = schema.validate(req.query.email);
  if (error) return res.redirect('/admin');

  await userCollection.updateOne({ email: req.query.email }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});

// GET /admin/demote
app.get('/admin/demote', async (req, res) => {
  if (!isAdmin(req)) return res.redirect('/login');

  const schema = Joi.string().email().max(100).required();
  const { error } = schema.validate(req.query.email);
  if (error) return res.redirect('/admin');

  await userCollection.updateOne({ email: req.query.email }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});

// GET /logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404
app.use((req, res) => {
  res.status(404).render('404', {
    title: 'Page Not Found',
    user: isLoggedIn(req) ? req.session.name : null,
    isAdmin: isAdmin(req)
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});