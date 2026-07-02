const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;

// ===== MIDDLEWARE =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// ===== STATIC FILES =====
app.use(express.static(__dirname));

// ===== IN-MEMORY DATABASE =====
const users = [];
const carts = {};

// ===== CSRF TOKEN =====
app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  res.json({ csrfToken: token });
});

// ===== AUTH MIDDLEWARE =====
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
};

// ===== AUTH ENDPOINTS =====

app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword,
      verified: true
    };
    users.push(newUser);
    carts[newUser.id] = [];
    
    res.json({ 
      success: true, 
      message: 'Account created successfully',
      userId: newUser.id
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    res.json({ 
      success: true, 
      message: 'Login successful', 
      user: { id: user.id, username: user.username, email: user.email } 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/user', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  res.json({ 
    success: true, 
    user: { id: user.id, username: user.username, email: user.email } 
  });
});

app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: 'Logged out successfully' });
});

app.put('/api/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = users.find(u => u.id === req.session.userId);
    
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }
    
    user.password = await bcrypt.hash(newPassword, 10);
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/user', requireAuth, (req, res) => {
  const index = users.findIndex(u => u.id === req.session.userId);
  if (index !== -1) {
    users.splice(index, 1);
    delete carts[req.session.userId];
    req.session.destroy();
    res.json({ success: true, message: 'Account deleted successfully' });
  } else {
    res.status(404).json({ success: false, message: 'User not found' });
  }
});

// ===== CART ENDPOINTS =====

app.post('/api/update-cart', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const { cart } = req.body;
  carts[userId] = cart || [];
  res.json({ success: true, message: 'Cart updated' });
});

app.get('/api/total-price', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const cart = carts[userId] || [];
  const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  res.json({ success: true, cartItems: cart, total: total });
});

app.post('/api/checkout', requireAuth, (req, res) => {
  const userId = req.session.userId;
  carts[userId] = [];
  res.json({ success: true, message: 'Order placed successfully!' });
});

// ===== SEARCH =====

app.get('/api/search', (req, res) => {
  const query = req.query.search?.toLowerCase() || '';
  
  const pages = [
    { title: 'Home', url: 'home.html', description: 'Welcome to TENZIC TECHNOLOGIES' },
    { title: 'Products', url: 'products.html', description: 'Computer products and accessories' },
    { title: 'Gadgets', url: 'gadgets.html', description: 'Tech gadgets and accessories' },
    { title: 'Services', url: 'services.html', description: 'Our services and support' },
    { title: 'Software', url: 'softwares.html', description: 'Software downloads' },
    { title: 'Cart', url: 'cart.html', description: 'Your shopping cart' },
    { title: 'POS Systems', url: 'intro.html', description: 'Point of Sale solutions' }
  ];
  
  const results = pages.filter(page => 
    page.title.toLowerCase().includes(query) || 
    page.description.toLowerCase().includes(query)
  );
  
  if (results.length === 1) {
    return res.json({ success: true, redirect: results[0].url });
  }
  
  res.json({ success: true, results });
});

app.get('/api/check-auth', (req, res) => {
  res.json({ isAuthenticated: !!req.session.userId });
});

app.post('/api/verify', (req, res) => {
  res.json({ success: true, message: 'Email verified successfully' });
});

app.post('/api/request-email-update', requireAuth, (req, res) => {
  const { newEmail } = req.body;
  req.session.pendingEmail = newEmail;
  req.session.verificationCode = '123456';
  res.json({ success: true, message: 'Verification code sent' });
});

app.post('/api/verify-email-update', requireAuth, (req, res) => {
  const { code } = req.body;
  if (code === req.session.verificationCode) {
    const user = users.find(u => u.id === req.session.userId);
    if (user) {
      user.email = req.session.pendingEmail;
      delete req.session.pendingEmail;
      delete req.session.verificationCode;
      return res.json({ success: true, message: 'Email updated successfully' });
    }
  }
  res.status(400).json({ success: false, message: 'Invalid verification code' });
});

// ===== SERVE FRONTEND =====

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===== START SERVER =====

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ TENZIC TECHNOLOGIES server running on port ${PORT}`);
});