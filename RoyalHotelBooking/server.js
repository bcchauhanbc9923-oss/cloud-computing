
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const Booking = require('./models/Booking');
const Contact = require('./models/Contact');
const User = require('./models/User');

const app = express();
const port = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI;
const tokenSecret = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

function createToken(user) {
    const payload = Buffer.from(JSON.stringify({
        id: user._id.toString(),
        email: user.email,
        exp: Date.now() + 7 * 24 * 60 * 60 * 1000
    })).toString('base64url');

    const signature = crypto
        .createHmac('sha256', tokenSecret)
        .update(payload)
        .digest('base64url');

    return `${payload}.${signature}`;
}

function requireAuth(req, res, next) {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');

    if (!token) {
        return res.status(401).json({ error: 'Please log in to continue.' });
    }

    const [payload, signature] = token.split('.');

    if (!payload || !signature) {
        return res.status(401).json({ error: 'Invalid login session.' });
    }

    const expected = crypto
        .createHmac('sha256', tokenSecret)
        .update(payload)
        .digest();

    let actual;

    try {
        actual = Buffer.from(signature, 'base64url');
    } catch {
        return res.status(401).json({ error: 'Invalid login session.' });
    }

    if (actual.length !== expected.length ||
        !crypto.timingSafeEqual(actual, expected)) {
        return res.status(401).json({ error: 'Invalid login session.' });
    }

    try {
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString());

        if (!data.id || data.exp < Date.now()) {
            return res.status(401).json({
                error: 'Your session has expired. Please log in again.'
            });
        }

        req.user = data;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid login session.' });
    }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, original] = (stored || '').split(':');

    if (!salt || !original) return false;

    const candidate = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(original, 'hex');

    return candidate.length === expected.length &&
        crypto.timingSafeEqual(candidate, expected);
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/auth/signup', async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        if (!name || !email ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            password.length < 8) {
            return res.status(400).json({
                error: 'Enter your name, a valid email, and a password with at least 8 characters.'
            });
        }

        if (await User.findOne({ email })) {
            return res.status(409).json({
                error: 'An account with this email already exists. Please log in.'
            });
        }

        const user = await User.create({
            name,
            email,
            passwordHash: hashPassword(password)
        });

        res.status(201).json({
            message: 'Account created successfully.',
            token: createToken(user),
            user: { name: user.name, email: user.email }
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Unable to create account.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        const user = await User.findOne({ email });

        if (!user || !verifyPassword(password, user.passwordHash)) {
            return res.status(401).json({
                error: 'Incorrect email or password.'
            });
        }

        res.json({
            message: 'Login successful.',
            token: createToken(user),
            user: { name: user.name, email: user.email }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Unable to log in.' });
    }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('name email');

        if (!user) {
            return res.status(401).json({
                error: 'Account not found. Please log in again.'
            });
        }

        res.json({ user });
    } catch (error) {
        res.status(500).json({ error: 'Unable to verify account.' });
    }
});

app.post('/api/bookings', requireAuth, async (req, res) => {
    try {
        const { name, email, phone, guests, checkin, checkout, room, request } = req.body;

        const start = new Date(`${checkin}T00:00:00`);
        const end = new Date(`${checkout}T00:00:00`);

        if (!name || !email || !checkin || !checkout ||
            Number.isNaN(start.getTime()) ||
            Number.isNaN(end.getTime()) ||
            end <= start) {
            return res.status(400).json({
                error: 'Please enter valid details. Check-out must be after check-in.'
            });
        }

        const guestCount = Number(guests);

        if (!Number.isInteger(guestCount) || guestCount < 1 || guestCount > 20) {
            return res.status(400).json({
                error: 'Guests must be between 1 and 20.'
            });
        }

        const booking = new Booking({
            name: String(name).trim(),
            email: String(email).trim().toLowerCase(),
            phone,
            guests: guestCount,
            checkin: start,
            checkout: end,
            room,
            request,
            user: req.user.id
        });

        const savedBooking = await booking.save();

        res.status(201).json(savedBooking);

    } catch (error) {
        console.error('Booking error:', error);
        res.status(400).json({
            error: error.message || 'Unable to create booking.'
        });
    }
});

app.get('/api/bookings', requireAuth, async (req, res) => {
    try {
        const bookings = await Booking.find({
            user: req.user.id
        }).sort({ createdAt: -1 });

        res.json(bookings);
    } catch (error) {
        console.error('Fetch bookings error:', error);
        res.status(500).json({ error: 'Unable to fetch bookings.' });
    }
});

app.post('/api/contacts', async (req, res) => {
    try {
        const contact = new Contact(req.body);
        const savedContact = await contact.save();

        res.status(201).json(savedContact);
    } catch (error) {
        console.error('Contact error:', error);
        res.status(400).json({ error: 'Unable to save contact message.' });
    }
});

app.get('/api/contacts', async (req, res) => {
    try {
        const contacts = await Contact.find().sort({ createdAt: -1 });
        res.json(contacts);
    } catch (error) {
        res.status(500).json({ error: 'Unable to fetch contact messages.' });
    }
});

if (!mongoUri || !tokenSecret) {
    console.error('Please configure MONGODB_URI and JWT_SECRET in your .env file.');
    process.exit(1);
}

mongoose.connect(mongoUri)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(port, () => {
            console.log(`Royal Hotel website running at http://localhost:${port}`);
        });
    })
    .catch(error => {
        console.error('MongoDB connection error:', error.message);
        process.exit(1);
    });
