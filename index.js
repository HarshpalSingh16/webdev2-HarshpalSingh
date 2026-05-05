require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

// MongoDB connection
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

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Session setup
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUrl,
    dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions',
    crypto: {
      secret: process.env.MONGODB_SESSION_SECRET
    },
    ttl: 3600 // 1 hour in seconds
  }),
  cookie: {
    maxAge: 60 * 60 * 1000 // 1 hour in milliseconds
  }
}));

// Helper: check if logged in
function isLoggedIn(req) {
  return req.session && req.session.authenticated;
}

// Shared page styles
const styles = `<style>

body{
font-family:Tahoma,sans-serif;
background:#c0c0c0;
display:flex;
justify-content:center;
align-items:center;
min-height:100vh;
padding:20px
}

.card{
background:#fff;
border:2px solid #808080;
padding:20px;
width:320px;
text-align:center
}

h1,h2{
color:#000080;
font-size:18px
}

input{
width:100%;
padding:6px;
margin:6px 0;
border:1px solid #808080
}

button,.btn{
width:100%;
padding:6px;
margin-top:6px;
background:#d4d0c8;
border:2px solid #808080;
cursor:pointer;
text-decoration:none;
display:block;
box-sizing:border-box
}

button:hover,.btn:hover{
background:#ece9d8
}

.member-img{
width:250px;
height:200px;
object-fit:cover;
border:1px solid #808080;
margin:10px auto;
display:block
}

a{
color:#000080
}

.error{
color:red;
font-size:12px
}
</style>`;

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  ${styles}
</head>
<body>
  <div class="card">
    ${body}
  </div>
</body>
</html>`;
}

// ==================== ROUTES ====================

// GET /
app.get('/', (req, res) => {
  if (isLoggedIn(req)) {
    res.send(page('Home', `
      <h1>👋 Hello, ${req.session.name}!</h1>
      <p>Welcome back to the Members Club.</p>
      <a href="/members" class="btn">Go to Members Area</a>
      <a href="/logout" class="btn btn-danger">Sign Out</a>
    `));
  } else {
    res.send(page('Home', `
      <h1>🔐 Members Club</h1>
      <p>Please sign up or log in to access the members area.</p>
      <a href="/signup" class="btn">Sign Up</a>
      <a href="/login" class="btn btn-outline">Log In</a>
    `));
  }
});

// GET /signup
app.get('/signup', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/members');
  res.send(page('Sign Up', `
    <h1>Create Account</h1>
    <form action="/signupSubmit" method="POST">
      <input type="text" name="name" placeholder="Full Name" required />
      <input type="email" name="email" placeholder="Email Address" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Sign Up</button>
    </form>
    <div class="divider">Already have an account?</div>
    <a href="/login">Log In</a>
  `));
});

// POST /signupSubmit
app.post('/signupSubmit', async (req, res) => {
  const { name, email, password } = req.body;

  // Validate inputs
  if (!name) {
    return res.send(page('Sign Up Error', `
      <h1>Sign Up Error</h1>
      <p class="error">Name is required.</p>
      <a href="/signup" class="btn">Try Again</a>
    `));
  }
  if (!email) {
    return res.send(page('Sign Up Error', `
      <h1>Sign Up Error</h1>
      <p class="error">Please provide an email address.</p>
      <a href="/signup" class="btn">Try Again</a>
    `));
  }
  if (!password) {
    return res.send(page('Sign Up Error', `
      <h1>Sign Up Error</h1>
      <p class="error">Password is required.</p>
      <a href="/signup" class="btn">Try Again</a>
    `));
  }

  // Joi validation (NoSQL injection protection)
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    return res.send(page('Sign Up Error', `
      <h1>Sign Up Error</h1>
      <p class="error">Invalid input: ${validationResult.error.details[0].message}</p>
      <a href="/signup" class="btn">Try Again</a>
    `));
  }

  try {
    // Check if email already exists
    const existing = await userCollection.findOne({ email: email });
    if (existing) {
      return res.send(page('Sign Up Error', `
        <h1>Sign Up Error</h1>
        <p class="error">An account with that email already exists.</p>
        <a href="/signup" class="btn">Try Again</a>
        <a href="/login" class="btn btn-outline">Log In</a>
      `));
    }

    // Hash password and store user
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword });

    // Create session
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;

    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.send(page('Error', `<p class="error">Server error. Please try again.</p><a href="/signup" class="btn">Try Again</a>`));
  }
});

// GET /login
app.get('/login', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/members');
  res.send(page('Log In', `
    <h1>Welcome Back</h1>
    <form action="/loginSubmit" method="POST">
      <input type="email" name="email" placeholder="Email Address" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Log In</button>
    </form>
    <div class="divider">Don't have an account?</div>
    <a href="/signup">Sign Up</a>
  `));
});

// POST /loginSubmit
app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;

  // Joi validation (NoSQL injection protection)
  const schema = Joi.object({
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    return res.send(page('Login Error', `
      <h1>Login Error</h1>
      <p class="error">Invalid input.</p>
      <a href="/login" class="btn">Try Again</a>
    `));
  }

  try {
    const user = await userCollection.findOne({ email: email });

    if (!user) {
      return res.send(page('Login Error', `
        <h1>Login Error</h1>
        <p class="error">Invalid email/password combination.</p>
        <a href="/login" class="btn">Try Again</a>
      `));
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.send(page('Login Error', `
        <h1>Login Error</h1>
        <p class="error">Invalid email/password combination.</p>
        <a href="/login" class="btn">Try Again</a>
      `));
    }

    // Create session
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    res.redirect('/members');
  } catch (err) {
    console.error(err);
    res.send(page('Error', `<p class="error">Server error. Please try again.</p><a href="/login" class="btn">Try Again</a>`));
  }
});

// GET /members
app.get('/members', (req, res) => {
  if (!isLoggedIn(req)) {
    return res.redirect('/');
  }

  const images = ['space.jpg', 'space2.jpg', 'space3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(page('Members Area', `
    <h1>Hello, ${req.session.name}.</h1>
    <p>Welcome to the members-only area! 🎉</p>
    <img src="/images/${randomImage}" alt="Random image" class="member-img" />
    <a href="/logout" class="btn btn-danger">Sign Out</a>
    <a href="/" class="btn btn-outline">Home</a>
  `));
});

// GET /logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404 catch-all
app.use((req, res) => {
  res.status(404).send(page('Page Not Found', `
    <h1>404</h1>
    <p>Page not found.</p>
    <a href="/" class="btn">Go Home</a>
  `));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});