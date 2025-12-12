// index.js (final, production-safe cookie handling + delete-user endpoint)
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require("firebase-admin");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const stripeKey = process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET;
if (!stripeKey) console.error("FATAL: STRIPE_SECRET_KEY is missing!");
else console.log("Stripe Key Loaded: " + stripeKey + "...");
const stripe = require('stripe')(stripeKey);

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Render/Vercel)
const port = process.env.PORT || 5000;

// Initialize Firebase Admin
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } catch (e) {
        console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT", e);
    }
} else {
    try {
        serviceAccount = require("./styledecor-Admin-SDK.json");
    } catch (e) {
        console.warn("Local Firebase SDK file not found.");
    }
}

if (serviceAccount) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
} else {
    console.error("Firebase Admin SDK not initialized. Missing credentials.");
}

const allowedOrigins = [
    process.env.CLIENT_URL,
    'https://style-decor-client-two.vercel.app',
    'http://localhost:5173',
    'http://127.0.0.1:5173'
].filter(Boolean);

// Middleware
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests without origin (mobile apps, curl, Postman)
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin)) {
            return callback(null, origin);
        } else {
            console.log("CORS Blocked:", origin);
            return callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// ------------------------
// Cookie helper (production-safe)
// ------------------------

function buildCookieOptions(req) {
    const originHeader = (req.headers.origin || "").toString();
    // Treat empty origin (curl/Postman/server-to-server) as local-like to avoid blocking
    const isLocalOrigin =
        originHeader === "" ||
        originHeader.includes('localhost') ||
        originHeader.includes('127.0.0.1');

    const cookieDomain = process.env.COOKIE_DOMAIN || undefined; // e.g. ".yourdomain.com"
    const base = {
        httpOnly: true,
        secure: !isLocalOrigin,
        sameSite: isLocalOrigin ? 'lax' : 'none',
        path: '/',
    };

    if (cookieDomain) base.domain = cookieDomain;

    // Helpful debugging (remove or lower log level in production)
    console.debug('[Cookie Options]', { origin: originHeader, isLocalOrigin, domain: cookieDomain, secure: base.secure, sameSite: base.sameSite });

    return base;
}

// JWT helpers
const generateAccessToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '15m' });
};
const generateRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' });
};

// JWT verification middleware (cookie)
const verifyJWT = (req, res, next) => {
    const token = req.cookies?.accessToken;
    if (!token) return res.status(401).send({ message: 'Unauthorized access' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send({ message: 'Invalid access token' });
        req.decoded_email = decoded.email;
        req.decoded_role = decoded.role;
        next();
    });
};

const verifyAdmin = (req, res, next) => {
    if (req.decoded_role !== 'admin') return res.status(403).send({ message: 'Forbidden - Admin only' });
    next();
};

// MongoDB setup
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        await client.connect();

        // Collections
        const db = client.db('StyleDecorDB');
        const usersCollection = db.collection('users');
        const servicesCollection = db.collection('services');
        const bookingsCollection = db.collection('bookings');
        const paymentsCollection = db.collection('payments');
        const applicationsCollection = db.collection('applications');
        const wishlistCollection = db.collection('wishlist');
        const reviewsCollection = db.collection('reviews');
        const messagesCollection = db.collection('messages');
        const portfoliosCollection = db.collection('portfolios');

        app.get('/', (req, res) => res.send('StyleDecor Server is running'));

        // ================= WISHLIST =================
        app.post('/wishlist', verifyJWT, async (req, res) => {
            const item = req.body;
            const exists = await wishlistCollection.findOne({
                userEmail: item.userEmail,
                serviceId: item.serviceId
            });
            if (exists) return res.send({ message: 'Already in wishlist', insertedId: null });
            const result = await wishlistCollection.insertOne(item);
            res.send(result);
        });

        app.get('/wishlist', verifyJWT, async (req, res) => {
            const email = req.decoded_email;
            const result = await wishlistCollection.find({ userEmail: email }).toArray();
            res.send(result);
        });

        app.delete('/wishlist/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const result = await wishlistCollection.deleteOne({ _id: new ObjectId(id) });
            res.send(result);
        });

        // ================= REVIEWS =================
        app.post('/reviews', verifyJWT, async (req, res) => {
            const review = req.body;
            review.createdAt = new Date();
            const result = await reviewsCollection.insertOne(review);
            res.send(result);
        });

        app.get('/reviews/:serviceId', async (req, res) => {
            const serviceId = req.params.serviceId;
            const result = await reviewsCollection.find({ serviceId }).sort({ createdAt: -1 }).toArray();
            res.send(result);
        });

        // ================= MESSAGING =================
        app.post('/messages', verifyJWT, async (req, res) => {
            const message = req.body;
            message.createdAt = new Date();
            message.read = false;
            const result = await messagesCollection.insertOne(message);
            res.send(result);
        });

        app.get('/messages/:bookingId', verifyJWT, async (req, res) => {
            const bookingId = req.params.bookingId;
            const result = await messagesCollection.find({ bookingId }).sort({ createdAt: 1 }).toArray();
            res.send(result);
        });

        app.patch('/messages/mark-read/:bookingId', verifyJWT, async (req, res) => {
            const bookingId = req.params.bookingId;
            const userEmail = req.decoded_email;
            const filter = {
                bookingId,
                senderEmail: { $ne: userEmail },
                read: false
            };
            const updateDoc = { $set: { read: true } };
            const result = await messagesCollection.updateMany(filter, updateDoc);
            res.send(result);
        });

        // ================= PORTFOLIOS =================
        app.post('/portfolios', verifyJWT, async (req, res) => {
            const item = req.body;
            item.createdAt = new Date();
            item.decoratorEmail = req.decoded_email;
            const result = await portfoliosCollection.insertOne(item);
            res.send(result);
        });

        app.get('/portfolios', async (req, res) => {
            const result = await portfoliosCollection.find().sort({ createdAt: -1 }).toArray();
            res.send(result);
        });

        app.get('/portfolios/my-portfolio', verifyJWT, async (req, res) => {
            const email = req.decoded_email;
            const result = await portfoliosCollection.find({ decoratorEmail: email }).sort({ createdAt: -1 }).toArray();
            res.send(result);
        });

        // ================= AUTH =================
        // Firebase login: client posts idToken; server verifies and issues cookies
        app.post('/auth/firebase-login', async (req, res) => {
            try {
                const { idToken } = req.body;
                if (!idToken) return res.status(400).send({ message: 'idToken required' });

                const decoded = await admin.auth().verifyIdToken(idToken);
                const email = decoded.email;
                if (!email) return res.status(400).send({ message: 'Invalid Firebase token' });

                const displayName = decoded.name || '';
                const photoURL = decoded.picture || '';

                // Upsert user
                await usersCollection.updateOne(
                    { email },
                    {
                        $setOnInsert: {
                            email,
                            name: displayName,
                            photoURL,
                            role: 'user',
                            createdAt: new Date()
                        }
                    },
                    { upsert: true }
                );

                const user = await usersCollection.findOne({ email });

                const accessToken = generateAccessToken({ email, role: user.role });
                const refreshToken = generateRefreshToken({ email });

                // store refresh token in DB (for revocation + rotation)
                await usersCollection.updateOne({ email }, { $set: { refreshToken } });

                // Use production-safe cookie options based on request origin
                const baseOptions = buildCookieOptions(req);

                // clear old cookies before setting new ones (avoid duplicates)
                res.clearCookie('accessToken', baseOptions);
                res.clearCookie('refreshToken', baseOptions);

                res.cookie('accessToken', accessToken, { ...baseOptions, maxAge: 15 * 60 * 1000 });
                res.cookie('refreshToken', refreshToken, { ...baseOptions, maxAge: 7 * 24 * 60 * 60 * 1000 });

                return res.json({ message: 'Login successful', role: user.role });
            } catch (err) {
                console.error('firebase-login error:', err);
                return res.status(401).send({ message: 'Invalid Firebase token' });
            }
        });

        // Refresh endpoint (rotates refresh token)
        app.post('/auth/refresh-token', async (req, res) => {
            try {
                const oldRefreshToken = req.cookies?.refreshToken;
                if (!oldRefreshToken) return res.status(401).send({ message: 'No refresh token' });

                // Find user by stored refreshToken
                const user = await usersCollection.findOne({ refreshToken: oldRefreshToken });
                if (!user) return res.status(403).send({ message: 'Invalid refresh token' });

                jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
                    if (err) {
                        // invalid token, remove stored token for safety
                        await usersCollection.updateOne({ refreshToken: oldRefreshToken }, { $unset: { refreshToken: "" } });
                        return res.status(403).send({ message: 'Invalid refresh token' });
                    }

                    // Re-read fresh user role (in case role changed)
                    const freshUser = await usersCollection.findOne({ email: decoded.email });
                    if (!freshUser) return res.status(403).send({ message: 'User not found' });

                    const newAccessToken = generateAccessToken({ email: decoded.email, role: freshUser.role || 'user' });
                    const newRefreshToken = generateRefreshToken({ email: decoded.email });

                    // Persist rotated refresh token
                    await usersCollection.updateOne({ email: decoded.email }, { $set: { refreshToken: newRefreshToken } });

                    const baseOptions = buildCookieOptions(req);

                    // Replace cookies (clear first then set)
                    res.clearCookie('accessToken', baseOptions);
                    res.clearCookie('refreshToken', baseOptions);

                    res.cookie('accessToken', newAccessToken, { ...baseOptions, maxAge: 15 * 60 * 1000 });
                    res.cookie('refreshToken', newRefreshToken, { ...baseOptions, maxAge: 7 * 24 * 60 * 60 * 1000 });

                    return res.json({ message: 'Access token refreshed' });
                });
            } catch (err) {
                console.error('refresh-token error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // Logout
        app.post('/auth/logout', async (req, res) => {
            try {
                const refreshToken = req.cookies?.refreshToken;
                if (refreshToken) {
                    await usersCollection.updateOne({ refreshToken }, { $unset: { refreshToken: "" } });
                }

                const baseOptions = buildCookieOptions(req);

                res.clearCookie('accessToken', baseOptions);
                res.clearCookie('refreshToken', baseOptions);

                return res.json({ message: 'Logged out' });
            } catch (err) {
                console.error('logout error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // ================= USER PROFILE =================
        app.get('/users/me', verifyJWT, async (req, res) => {
            try {
                const email = req.decoded_email;
                let user = await usersCollection.findOne({ email }, { projection: { refreshToken: 0 } });
                if (!user) return res.status(404).send({ message: 'User not found' });

                // Backward compatibility: Generate referral code if missing
                if (!user.referralCode) {
                    const newCode = Math.random().toString(36).substring(2, 8).toUpperCase();
                    await usersCollection.updateOne(
                        { email: user.email },
                        { $set: { referralCode: newCode, referralRewards: [] } }
                    );
                    user.referralCode = newCode;
                    user.referralRewards = [];
                }

                return res.json({ user });
            } catch (err) {
                console.error(err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // ================= ADMIN / USERS =================
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        app.get('/decorators', async (req, res) => {
            const result = await usersCollection.find({ role: 'decorator' }).toArray();
            res.send(result);
        });

        // Update user role and status (Admin). Invalidate refresh token on role change.
        app.patch('/users/role/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { role, status } = req.body;
            const filter = { _id: new ObjectId(id) };

            const updateFields = {};
            if (role) updateFields.role = role;
            if (status) updateFields.status = status;

            const updateDoc = { $set: updateFields };
            const result = await usersCollection.updateOne(filter, updateDoc);

            // If role changed, unset refreshToken to force re-login
            if (result.modifiedCount > 0 && role) {
                await usersCollection.updateOne(filter, { $unset: { refreshToken: "" } });
                console.log(`User role updated and refreshToken invalidated for user id: ${id}`);
            }

            res.send(result);
        });

        // Delete user (Admin only)
        app.delete('/users/:id', verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await usersCollection.deleteOne(query);

                if (result.deletedCount === 0) {
                    return res.status(404).send({ message: 'User not found' });
                }

                return res.json({ success: true, message: 'User deleted successfully' });
            } catch (err) {
                console.error('delete user error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // ================= APPLICATIONS =================
        app.post('/applications', verifyJWT, async (req, res) => {
            const application = req.body;
            const existingApplication = await usersCollection.findOne({ email: application.email, status: 'requested' });
            if (existingApplication) return res.send({ message: 'Already applied' });

            const filter = { email: application.email };
            const updateDoc = {
                $set: {
                    status: 'requested',
                    specialty: application.specialty,
                    experience: application.experience,
                    portfolio: application.portfolio,
                    description: application.description
                }
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // ================= SERVICES =================
        app.post('/services', verifyJWT, verifyAdmin, async (req, res) => {
            const service = req.body;
            const result = await servicesCollection.insertOne(service);
            res.send(result);
        });

        app.delete('/services/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await servicesCollection.deleteOne(query);
            res.send(result);
        });

        app.patch('/services/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedService = req.body;
            const updateDoc = { $set: { ...updatedService } };
            const result = await servicesCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // ================= BOOKINGS =================
        app.post('/bookings', verifyJWT, async (req, res) => {
            const booking = req.body;
            booking.createdAt = new Date();
            booking.status = 'pending';
            const result = await bookingsCollection.insertOne(booking);
            res.send(result);
        });

        app.get('/bookings', verifyJWT, async (req, res) => {
            const role = req.decoded_role;
            const email = req.decoded_email;
            const page = parseInt(req.query.page) || 0;
            const limit = parseInt(req.query.limit) || 10;
            const skip = page * limit;

            let query = {};
            if (role === 'user') query = { userEmail: email };
            else if (role === 'decorator') query = { decoratorEmail: email };

            console.log(`API: Get Bookings - Role: ${role}, Email: ${email}`);

            let result = await bookingsCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();

            if (role === 'user' || role === 'decorator') {
                for (const booking of result) {
                    const unreadCount = await messagesCollection.countDocuments({
                        bookingId: booking._id.toString(),
                        senderEmail: { $ne: email },
                        read: false
                    });
                    booking.unreadCount = unreadCount;
                }
            }

            const total = await bookingsCollection.countDocuments(query);

            res.send({ data: result, total, limit, page });
        });

        app.delete('/bookings/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const email = req.decoded_email;
            const role = req.decoded_role;

            const query = { _id: new ObjectId(id) };
            if (role === 'user') {
                query.userEmail = email;
                query.status = 'pending';
            }

            const result = await bookingsCollection.deleteOne(query);
            res.send(result);
        });

        app.patch('/bookings/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const { status, decoratorEmail } = req.body;
            const filter = { _id: new ObjectId(id) };

            let updateDoc = { $set: {} };
            if (status) updateDoc.$set.status = status;
            if (decoratorEmail) updateDoc.$set.decoratorEmail = decoratorEmail;

            const result = await bookingsCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        app.get('/bookings/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            console.log("API: Fetching booking ID:", id);
            const query = { _id: new ObjectId(id) };
            const result = await bookingsCollection.findOne(query);
            console.log("API: Found booking:", result);
            res.send(result);
        });

        // ================= PAYMENTS =================
        app.post('/create-payment-intent', verifyJWT, async (req, res) => {
            try {
                const { price } = req.body;
                if (!price || isNaN(price)) return res.status(400).send({ message: 'Invalid price' });
                const amount = Math.round(Number(price) * 100);

                const paymentIntent = await stripe.paymentIntents.create({
                    amount,
                    currency: 'usd',
                    automatic_payment_methods: { enabled: true },
                });

                res.send({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                console.error("Error creating payment intent:", error);
                res.status(500).send({ message: error.message });
            }
        });

        app.post('/payment-checkout-session', async (req, res) => {
            const paymentInfo = req.body;
            const costInDollars = parseFloat(paymentInfo.cost);
            if (isNaN(costInDollars) || costInDollars <= 0) return res.status(400).send({ message: 'Invalid or missing cost parameter.' });

            const amount = Math.round(costInDollars * 100);

            const session = await stripe.checkout.sessions.create({
                line_items: [{
                    price_data: {
                        currency: 'usd',
                        unit_amount: amount,
                        product_data: { name: `Paying for: ${paymentInfo.parcelName}` }
                    },
                    quantity: 1,
                }],
                customer_email: paymentInfo.senderEmail,
                mode: 'payment',
                metadata: {
                    bookingId: paymentInfo.bookingId,
                    parcelId: paymentInfo.parcelId,
                    parcelName: paymentInfo.parcelName
                },
                success_url: `${process.env.CLIENT_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_URL}/dashboard/payment-canceled`,
            });

            res.send({ url: session.url });
        });

        app.patch('/payment-success', async (req, res) => {
            const { session_id } = req.query;
            try {
                const session = await stripe.checkout.sessions.retrieve(session_id);

                if (session.payment_status === 'paid') {
                    const payment = {
                        transactionId: session.payment_intent,
                        email: session.customer_email,
                        amount: session.amount_total / 100,
                        date: new Date(),
                        bookingId: session.metadata.bookingId,
                        parcelId: session.metadata.parcelId,
                        status: 'paid',
                        parcelName: session.metadata.parcelName
                    };

                    const result = await paymentsCollection.insertOne(payment);

                    const bookingId = session.metadata.bookingId;
                    if (bookingId) {
                        const filter = { _id: new ObjectId(bookingId) };
                        const updateDoc = { $set: { status: 'paid' } };
                        await bookingsCollection.updateOne(filter, updateDoc);
                    }

                    res.send({ success: true, transactionId: payment.transactionId, trackingId: result.insertedId });
                } else {
                    res.status(400).send({ message: 'Payment not paid' });
                }
            } catch (error) {
                console.error("Error verifying payment:", error);
                res.status(500).send({ message: error.message });
            }
        });

        app.post('/payments', verifyJWT, async (req, res) => {
            const payment = req.body;
            const paymentResult = await paymentsCollection.insertOne(payment);
            const query = { _id: { $in: payment.bookingIds.map(id => new ObjectId(id)) } };
            const updatedDoc = { $set: { status: 'paid' } };
            const updatedResult = await bookingsCollection.updateMany(query, updatedDoc);
            res.send({ paymentResult, updatedResult });
        });

        app.get('/payments/:email', verifyJWT, async (req, res) => {
            const query = { email: req.params.email };
            const result = await paymentsCollection.find(query).toArray();
            res.send(result);
        });

        // ================= DECORATOR FEATURES =================
        app.post('/applications', async (req, res) => {
            try {
                const application = req.body;
                application.createdAt = new Date();
                application.status = 'pending';
                const existing = await applicationsCollection.findOne({ email: application.email });
                if (existing) return res.send({ message: 'Already applied', insertedId: null });
                const result = await applicationsCollection.insertOne(application);
                res.send(result);
            } catch (error) {
                console.error("Error submitting application:", error);
                res.status(500).send({ message: 'Server error' });
            }
        });

        app.get('/decorator/stats', verifyJWT, async (req, res) => {
            const email = req.decoded_email;
            const role = req.decoded_role;
            if (role !== 'decorator') return res.status(403).send({ message: 'Forbidden access' });

            try {
                const stats = await bookingsCollection.aggregate([
                    { $match: { decoratorEmail: email, status: { $in: ['paid', 'completed', 'in-progress'] } } },
                    {
                        $group: {
                            _id: null,
                            totalBookings: { $sum: 1 },
                            totalEarnings: { $sum: { $toDouble: "$price" } },
                            completedBookings: { $sum: { $cond: [{ $eq: ["$status", "completed"] }, 1, 0] } }
                        }
                    }
                ]).toArray();

                const data = stats.length > 0 ? stats[0] : { totalBookings: 0, totalEarnings: 0, completedBookings: 0 };
                res.send(data);
            } catch (error) {
                console.error("Error getting decorator stats:", error);
                res.status(500).send({ message: 'Server error' });
            }
        });

        // ================= ANALYTICS =================
        app.get('/admin/stats', verifyJWT, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await servicesCollection.estimatedDocumentCount();
            const bookings = await bookingsCollection.estimatedDocumentCount();

            const payments = await bookingsCollection.aggregate([{ $group: { _id: null, totalRevenue: { $sum: '$price' } } }]).toArray();
            const revenue = payments.length > 0 ? payments[0].totalRevenue : 0;

            res.send({ users, products, bookings, revenue });
        });

        app.listen(port, () => console.log(`Server running on port ${port}`));

    } catch (error) {
        console.error("Error in run:", error);
    } finally {
        // keep DB connection open
    }
}
run().catch(console.dir);
