const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');
const morgan = require('morgan');
const winston = require('winston');
const request = require('request');


const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const nodemailer = require('nodemailer');
const cors = require('cors');


require('dotenv').config();


const app = express();

const port = 3000;
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'asel3127',
  port: 5433,
});

const logger = winston.createLogger({
  level: 'info', // Минимальный уровень логирования
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // Логирование сообщений об ошибках в error.log
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    // Логирование всех сообщений в combined.log
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});


// Passport initialization
app.use(cors());
app.use(express.static('public'));
app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(require('express-session')({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

app.use((error, req, res, next) => {
  logger.error(error); // Log the error with Winston
  if (res.headersSent) {
    return next(error);
  }
  res.status(500).json({ error: 'Internal Server Error' });
});



passport.use(new LocalStrategy(
  async function (username, password, done) {
    try {
      // Replace this with your actual user authentication logic
      const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

      if (result.rows.length === 0) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const user = result.rows[0];

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    } catch (error) {
      return done(error);
    }
  }
));

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    // Replace this with your actual user retrieval logic
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return done(null, false);
    }

    const user = result.rows[0];
    return done(null, user);
  } catch (error) {
    return done(error);
  }
});

// isAuthenticated middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    const userRole = req.user.role;

    // Allow access based on user role
    switch (userRole) {
      case 'admin':
        if (req.path === '/moderator.html') {
          console.log('Unauthorized access!');
          return res.redirect('/login');
        }
        console.log('Authenticated admin:', req.user);
        return next();
      case 'moderator':
        console.log('Authenticated moderator:', req.user);
        return next();
      case 'user':
        // Ensure that the user can only access their own page
        if (req.path !== `/${userRole}.html`) {
          console.log('Unauthorized access!');
          return res.redirect('/login');
        }
        console.log('Authenticated user:', req.user);
        return next();
      default:
        console.log('Unauthorized access!');
        return res.redirect('/login');
    }
  }

  console.log('Not authenticated!');
  res.redirect('/login'); // Redirect to the login page if not authenticated
}


function isAdmin(req, res, next) {
  // Assuming you have some way to identify if the user is an admin
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).send('Access denied.');
  }
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});




async function sendVerificationEmail(userEmail, userId) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: 'Please verify your email',
    text: `Click this link to verify your email: http://localhost:3000/verify?id=${userId}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Verification email sent');
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw error; // Rethrow to handle it in the calling context
  }
}

app.get('/api/flashcards', (req, res) => {
  const options = {
    method: 'GET',
    url: 'https://real-estate-exam.p.rapidapi.com/flashcards',
    headers: {
      'X-RapidAPI-Key': process.env.RAPIDAPI_KEY,
      'X-RapidAPI-Host': 'real-estate-exam.p.rapidapi.com'
    }
  };

  request(options, (error, response, body) => {
    if (error) {
      console.error('Error making API call:', error);
      return res.status(500).json({ message: 'Error making API call' });
    }

    // Here you can modify the response as needed before sending it to the frontend
    res.status(200).json(JSON.parse(body));
  });
});
// Routes
app.post('/api/auth/signin', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ error: info.message });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      // Определите, куда нужно перенаправить пользователя, основываясь на его роли
      let redirectUrl;
      switch (user.role) {
        case 'admin':
          redirectUrl = '/admin.html';
          break;
        case 'moderator':
          redirectUrl = '/moderator.html';
          break;
        default:
          redirectUrl = '/user.html';
      }
      return res.json({ success: true, redirectUrl: redirectUrl });
    });
  })(req, res, next);
});


app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password, role } = req.body;

  // Add input validation for username and role if needed

  if (!email.includes('@')) {
    return res.status(400).send('Invalid email format.');
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(409).send('Email already in use.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, email, password, role, verified) VALUES ($1, $2, $3, $4, $5) RETURNING *';
    const values = [username, email, hashedPassword, role, 'not verified'];

    const result = await pool.query(query, values);
    await sendVerificationEmail(email, result.rows[0].id);

    res.status(200).send('User registered successfully. Please check your email for verification.');
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).send('Error registering user: ' + error.message);
  }
});

app.get('/api/users', isAuthenticated, async (req, res) => {
  try {
    // Select all necessary columns from the users table
    const result = await pool.query('SELECT username, email, role, verified FROM users');
    const users = result.rows;
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.post('/create-user', isAuthenticated, isAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;

  // Optional: Add input validation here
  if (!username || !email || !password || !role) {
    return res.status(400).json({ error: "Missing required user details." });
  }

  // Here you can add more sophisticated checks, like if the email is already taken
  try {
    // Check if the user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already in use." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    const newUser = await pool.query(
      'INSERT INTO users (username, email, password, role, verified) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [username, email, hashedPassword, role, false] // Assuming 'verified' is a boolean field
    );

    // Send welcome email with the login details (consider sending a link for setting the password instead of sending the password directly)
    await sendWelcomeEmail(email, password);

    res.status(201).json({
      message: "User created successfully",
      user: newUser.rows[0]
    });
  } catch (error) {
    console.error('User created successfully:', error);
    res.status(500).send('Error creating user. Please try again later.');
  }
});
async function isAdmin(req, res, next) {
  // Assuming req.user is set by isAuthenticated middleware
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: "Unauthorized: Admin role required" });
  }
}
async function sendWelcomeEmail(userEmail, userPassword) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: 'Welcome to the Admin Dashboard',
    text: `Welcome to the Admin Dashboard!\n\nYour login password is: ${userPassword}\n\nPlease keep this password secure.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Welcome email sent');
  } catch (error) {
    console.error('Error sending welcome email:', error);
    throw error; // Rethrow to handle it in the calling context
  }
}
app.get('/api/moderation/content', isAdmin, async (req, res) => {
  try {
    // Fetch only 'pending' content
    const pendingContent = await Content.find({ status: 'pending' });
    res.json(pendingContent);
  } catch (error) {
    res.status(500).send('Server error');
  }
});



app.delete('/api/users/:username',  async (req, res) => {
  const { username } = req.params;

  // Allow users to delete their own account or admins to delete any account
  if (req.user.username !== username && req.user.role !== 'admin') {
    return res.status(403).send('Unauthorized');
  }

  try {
    const result = await pool.query('DELETE FROM users WHERE username = $1', [username]);
    if (result.rowCount > 0) {
      res.status(200).send('User deleted successfully.');
    } else {
      res.status(404).send('User not found.');
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).send('Error deleting user.');
  }
});


app.get('/verify', async (req, res) => {
  const { id } = req.query;

  if (!id) {
      return res.status(400).send('Verification link is invalid or expired.');
  }

  try {
      const query = 'UPDATE users SET verified = $1 WHERE id = $2 AND verified = $3 RETURNING *';
      const values = ['verified', id, 'not verified'];
      const result = await pool.query(query, values);

      if (result.rows.length === 0) {
          return res.status(404).send('User not found or already verified.');
      }

      res.send('Email verified successfully!');
  } catch (error) {
      console.error('Verification error:', error);
      res.status(500).send('An error occurred during the verification process.');
  }
});

app.put('/api/users/:username', isAuthenticated, async (req, res) => {
  const { username } = req.params;
  const { email, password } = req.body; // Assuming you want to update these fields

  // Perform input validation as necessary

  try {
    // Hash the new password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the user in the database
    const query = 'UPDATE users SET email = $1, password = $2 WHERE username = $3 RETURNING *';
    const values = [email, hashedPassword, username];

    const result = await pool.query(query, values);

    if (result.rows.length > 0) {
      res.json({ message: 'User updated successfully', user: result.rows[0] });
    } else {
      res.status(404).send('User not found.');
    }
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).send('Error updating user.');
  }
});












app.get('/verify', async (req, res) => {
  const { id } = req.query;

  if (!id) {
      return res.status(400).send('Verification link is invalid or expired.');
  }

  try {
      const query = 'UPDATE users SET verified = $1 WHERE id = $2 AND verified = $3 RETURNING *';
      const values = ['verified', id, 'not verified'];
      const result = await pool.query(query, values);

      if (result.rows.length === 0) {
          return res.status(404).send('User not found or already verified.');
      }

      res.send('Email verified successfully!');
  } catch (error) {
      console.error('Verification error:', error);
      res.status(500).send('An error occurred during the verification process.');
  }
});

  

app.post('/api/auth/logout', (req, res) => {
  req.logout();
  res.redirect('/login.html');
});




app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'main.html'));
});
app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get(['/login', '/login.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});


app.get('/user.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'user.html'));
});
app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'profile.html'));
  });
app.get('/update-user.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'update-user.html'));
});

app.get('/admin.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});




app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});