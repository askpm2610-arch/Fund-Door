require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;
const HOME_DIR = path.join(__dirname, 'HOME');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const CAMPAIGNS_FILE = path.join(DATA_DIR, 'campaigns.json');
const PASSWORD_RESETS_FILE = path.join(DATA_DIR, 'password-resets.json');

app.use(express.json());
app.use(express.static(HOME_DIR, { index: false }));

app.get('/', (req, res) => {
  res.redirect('/index.html');
});

async function readJson(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data || '[]');
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    throw err;
  }
}

async function writeJson(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function hashPassword(password, salt = null) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return `${salt}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [salt, key] = stored.split(':');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return hash.toString('hex') === key;
}

async function readUsers() {
  return readJson(USERS_FILE);
}

async function writeUsers(users) {
  return writeJson(USERS_FILE, users);
}

async function readSessions() {
  return readJson(SESSIONS_FILE);
}

async function writeSessions(sessions) {
  return writeJson(SESSIONS_FILE, sessions);
}

async function readCampaigns() {
  return readJson(CAMPAIGNS_FILE);
}

async function writeCampaigns(campaigns) {
  return writeJson(CAMPAIGNS_FILE, campaigns);
}

async function readPasswordResets() {
  return readJson(PASSWORD_RESETS_FILE);
}

async function writePasswordResets(resets) {
  return writeJson(PASSWORD_RESETS_FILE, resets);
}

function createSessionToken() {
  return crypto.randomUUID();
}

function getAuthToken(req) {
  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7);
  }
  return null;
}

async function getAuthenticatedUser(req) {
  const token = getAuthToken(req);
  if (!token) return null;
  const sessions = await readSessions();
  const session = sessions.find((s) => s.token === token && new Date(s.expiresAt) > new Date());
  if (!session) return null;
  const users = await readUsers();
  return users.find((u) => u.id === session.userId) || null;
}

async function createTransporter() {
  if (process.env.NO_EMAIL_OTP === 'true') return null;
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: SMTP_SECURE === 'true',
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}

function isSmtpConfigured() {
  if (process.env.NO_EMAIL_OTP === 'true') return false;
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  return Boolean(SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS);
}

async function sendOtpEmail(email, otp) {
  const transporter = await createTransporter();
  const subject = 'Fund Door Password Reset Code';
  const text = `Your Fund Door password reset code is ${otp}. It expires in 15 minutes.`;
  const html = `<p>Your Fund Door password reset code is <strong>${otp}</strong>.</p><p>It expires in 15 minutes.</p>`;

  if (!transporter) {
    console.error('SMTP is not configured. Cannot send OTP email.');
    return {
      sent: false,
      message: 'SMTP is not configured. Cannot send OTP email.'
    };
  }

  const fromAddress = process.env.SMTP_FROM || process.env.SMTP_USER || 'Fund Door <no-reply@funddoor.local>';

  try {
    await transporter.sendMail({
      from: fromAddress,
      to: email,
      subject,
      text,
      html
    });
    return { sent: true, message: 'OTP has been sent to your email address.' };
  } catch (err) {
    console.error('OTP email send error:', err);
    return { sent: false, message: 'Failed to send OTP email. Please check SMTP settings and try again.' };
  }
}

async function createSession(userId) {
  const sessions = await readSessions();
  const token = createSessionToken();
  const newSession = {
    token,
    userId,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString()
  };
  sessions.push(newSession);
  await writeSessions(sessions);
  return token;
}

function isAdminUser(user) {
  return user && user.isAdmin === true;
}

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email, and password are required.' });
  }

  const users = await readUsers();
  const existing = users.find((user) => user.email.toLowerCase() === email.toLowerCase());

  if (existing) {
    return res.status(409).json({ message: 'Email already registered.' });
  }

  const newUser = {
    id: crypto.randomUUID(),
    name,
    email,
    password: hashPassword(password),
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeUsers(users);

  const token = await createSession(newUser.id);
  return res.status(201).json({ message: 'Account created successfully.', token, name: newUser.name });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const users = await readUsers();
  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase());

  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }

  const token = await createSession(user.id);
  return res.json({ message: 'Login successful.', token, name: user.name });
});

app.get('/api/me', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ message: 'Not authenticated.' });
  }

  return res.json({ id: user.id, name: user.name, email: user.email, isAdmin: Boolean(user.isAdmin) });
});

app.get('/api/admin/users', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user || !isAdminUser(user)) {
    return res.status(403).json({ message: 'Admin access required.' });
  }

  const users = await readUsers();
  const campaigns = await readCampaigns();
  const userDashboards = users.map((u) => {
    const myCampaigns = campaigns.filter((campaign) => campaign.ownerId === u.id);
    const backedCampaigns = campaigns.filter((campaign) => (campaign.pledges || []).some((p) => p.userId === u.id));
    const totalRaised = myCampaigns.reduce((sum, campaign) => sum + (campaign.pledged || 0), 0);
    return {
      id: u.id,
      name: u.name,
      email: u.email,
      isAdmin: Boolean(u.isAdmin),
      createdAt: u.createdAt,
      campaignCount: myCampaigns.length,
      backedCount: backedCampaigns.length,
      totalRaised,
      myCampaigns,
      backedCampaigns
    };
  });

  return res.json({ users: userDashboards });
});

app.patch('/api/admin/users/:id', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user || !isAdminUser(user)) {
    return res.status(403).json({ message: 'Admin access required.' });
  }

  const users = await readUsers();
  const targetIndex = users.findIndex((u) => u.id === req.params.id);
  if (targetIndex === -1) {
    return res.status(404).json({ message: 'User not found.' });
  }

  if (req.params.id === user.id) {
    return res.status(400).json({ message: 'You cannot change your own admin status from here.' });
  }

  const targetUser = users[targetIndex];
  if (typeof req.body.isAdmin !== 'boolean') {
    return res.status(400).json({ message: 'isAdmin must be true or false.' });
  }

  targetUser.isAdmin = req.body.isAdmin;
  users[targetIndex] = targetUser;
  await writeUsers(users);
  return res.json({ message: 'User role updated.', user: { id: targetUser.id, isAdmin: targetUser.isAdmin } });
});

app.delete('/api/admin/users/:id', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user || !isAdminUser(user)) {
    return res.status(403).json({ message: 'Admin access required.' });
  }

  if (req.params.id === user.id) {
    return res.status(400).json({ message: 'You cannot delete your own admin account.' });
  }

  const users = await readUsers();
  const targetUser = users.find((u) => u.id === req.params.id);
  if (!targetUser) {
    return res.status(404).json({ message: 'User not found.' });
  }

  const remainingUsers = users.filter((u) => u.id !== req.params.id);
  await writeUsers(remainingUsers);

  const sessions = await readSessions();
  const remainingSessions = sessions.filter((session) => session.userId !== req.params.id);
  await writeSessions(remainingSessions);

  const campaigns = await readCampaigns();
  const remainingCampaigns = campaigns.filter((campaign) => campaign.ownerId !== req.params.id);
  await writeCampaigns(remainingCampaigns);

  return res.json({ message: 'User removed, and associated campaigns were deleted.' });
});

app.post('/api/logout', async (req, res) => {
  const token = getAuthToken(req);
  if (!token) {
    return res.json({ message: 'Logged out.' });
  }
  const sessions = await readSessions();
  const filtered = sessions.filter((session) => session.token !== token);
  await writeSessions(filtered);
  return res.json({ message: 'Logged out.' });
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  const users = await readUsers();
  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase());

  if (!user) {
    return res.status(404).json({ message: 'Email not found.' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 15).toISOString();
  const resets = await readPasswordResets();
  const filtered = resets.filter((item) => item.email.toLowerCase() !== email.toLowerCase());
  filtered.push({ email: email.toLowerCase(), otp, expiresAt });
  await writePasswordResets(filtered);

  const result = await sendOtpEmail(email, otp);
  if (!result.sent) {
    return res.status(500).json({ message: result.message });
  }
  return res.json({ message: result.message });
});

app.post('/api/reset-password', async (req, res) => {
  const { email, otp, password } = req.body;

  if (!email || !otp || !password) {
    return res.status(400).json({ message: 'Email, OTP, and new password are required.' });
  }

  const resets = await readPasswordResets();
  const resetRecord = resets.find((item) => item.email.toLowerCase() === email.toLowerCase() && item.otp === otp);
  if (!resetRecord) {
    return res.status(400).json({ message: 'Invalid OTP or email.' });
  }

  if (new Date(resetRecord.expiresAt) < new Date()) {
    return res.status(400).json({ message: 'OTP has expired.' });
  }

  const users = await readUsers();
  const userIndex = users.findIndex((u) => u.email.toLowerCase() === email.toLowerCase());
  if (userIndex === -1) {
    return res.status(404).json({ message: 'User not found.' });
  }

  users[userIndex].password = hashPassword(password);
  await writeUsers(users);
  await writePasswordResets(resets.filter((item) => item.email.toLowerCase() !== email.toLowerCase()));

  return res.json({ message: 'Password updated successfully. Please login with your new password.' });
});

app.post('/api/contact', async (req, res) => {
  const { name, email, subject, category, message } = req.body;
  if (!name || !email || !subject || !category || !message) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  const transporter = await createTransporter();
  if (!transporter) {
    return res.status(500).json({ message: 'Email service is not configured.' });
  }

  const adminEmail = process.env.ADMIN_EMAIL || process.env.SMTP_USER;
  const fromAddress = process.env.SMTP_FROM || process.env.SMTP_USER;

  try {
    await transporter.sendMail({
      from: fromAddress,
      to: adminEmail,
      subject: `[Fund Door Contact] ${subject}`,
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Category:</strong> ${category}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `
    });
    return res.json({ message: 'Your message has been sent successfully!' });
  } catch (err) {
    console.error('Contact email error:', err);
    return res.status(500).json({ message: 'Failed to send message. Please try again.' });
  }
});

app.post('/api/contact', async (req, res) => {
  const { name, email, subject, category, message } = req.body;
  if (!name || !email || !subject || !category || !message) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  const transporter = await createTransporter();
  if (!transporter) {
    return res.status(500).json({ message: 'Email service is not configured.' });
  }

  const adminEmail = process.env.ADMIN_EMAIL || process.env.SMTP_USER;
  const fromAddress = process.env.SMTP_FROM || process.env.SMTP_USER;

  try {
    await transporter.sendMail({
      from: fromAddress,
      to: adminEmail,
      subject: `[Fund Door Contact] ${subject}`,
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Category:</strong> ${category}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `
    });
    return res.json({ message: 'Your message has been sent successfully!' });
  } catch (err) {
    console.error('Contact email error:', err);
    return res.status(500).json({ message: 'Failed to send message. Please try again.' });
  }
});

app.get('/api/campaigns', async (req, res) => {
  const campaigns = await readCampaigns();
  return res.json(campaigns);
});

app.get('/api/campaigns/:id', async (req, res) => {
  const campaigns = await readCampaigns();
  const campaign = campaigns.find((c) => c.id === req.params.id);
  if (!campaign) {
    return res.status(404).json({ message: 'Campaign not found.' });
  }
  return res.json(campaign);
});

app.post('/api/campaigns', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  const { title, description, category, goal, imageUrl } = req.body;
  if (!title || !description || !category || !goal) {
    return res.status(400).json({ message: 'Title, description, category, and goal are required.' });
  }

  const campaigns = await readCampaigns();
  const newCampaign = {
    id: crypto.randomUUID(),
    title,
    description,
    category,
    goal: Number(goal),
    imageUrl: imageUrl || 'https://images.unsplash.com/photo-1518972559570-e7cc0aa5c534?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80',
    ownerId: user.id,
    ownerName: user.name,
    createdAt: new Date().toISOString(),
    pledged: 0,
    backers: 0,
    pledges: []
  };

  campaigns.push(newCampaign);
  await writeCampaigns(campaigns);

  return res.status(201).json({ message: 'Campaign created successfully.', campaign: newCampaign });
});

app.post('/api/campaigns/:id/pledge', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  const { amount } = req.body;
  const pledgeAmount = Number(amount);
  if (!pledgeAmount || pledgeAmount <= 0) {
    return res.status(400).json({ message: 'Please enter a valid pledge amount.' });
  }

  const campaigns = await readCampaigns();
  const campaignIndex = campaigns.findIndex((c) => c.id === req.params.id);
  if (campaignIndex === -1) {
    return res.status(404).json({ message: 'Campaign not found.' });
  }

  const campaign = campaigns[campaignIndex];
  campaign.pledges = campaign.pledges || [];
  campaign.pledges.push({ userId: user.id, name: user.name, amount: pledgeAmount, createdAt: new Date().toISOString() });
  campaign.pledged = campaign.pledges.reduce((sum, p) => sum + p.amount, 0);
  campaign.backers = campaign.pledges.length;

  campaigns[campaignIndex] = campaign;
  await writeCampaigns(campaigns);

  return res.json({ message: 'Thank you for your pledge!', campaign });
});

app.get('/api/my-campaigns', async (req, res) => {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  const campaigns = await readCampaigns();
  const myCampaigns = campaigns.filter((campaign) => campaign.ownerId === user.id);
  const backedCampaigns = campaigns.filter((campaign) => (campaign.pledges || []).some((p) => p.userId === user.id));
  return res.json({ myCampaigns, backedCampaigns });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(HOME_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`SMTP configured: ${isSmtpConfigured() ? 'yes' : 'no'}`);
  if (!isSmtpConfigured()) {
    console.log('Update .env with valid SMTP credentials and set NO_EMAIL_OTP=false to enable OTP email delivery.');
  }
});
