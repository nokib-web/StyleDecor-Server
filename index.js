const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require("firebase-admin");

const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const stripeKey = process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET;
const stripe = require('stripe')(stripeKey);

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Render/Vercel)
// const cors = require('cors');
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
        // The allowedOrigins array is now accessible here (Closure/Scope)

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

// JWT helpers
const generateAccessToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '15m' });
};
const generateRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' });
};

// JWT verification middleware (Header: Authorization: Bearer <token>)
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access' });
    }

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

        // All The collection
        const db = client.db('StyleDecorDB');
        const usersCollection = db.collection('users');
        const servicesCollection = db.collection('services');
        const bookingsCollection = db.collection('bookings');

        const paymentsCollection = db.collection('payments');
        const applicationsCollection = db.collection('applications');
        const wishlistCollection = db.collection('wishlist');
        const reviewsCollection = db.collection('reviews');
        const messagesCollection = db.collection('messages'); // New Chat Collection
        const portfoliosCollection = db.collection('portfolios');

        app.get('/', (req, res) => res.send('StyleDecor Server is running'));

        // ===========================================
        // WISHLIST ENDPOINTS
        // ===========================================

        // Add to Wishlist
        app.post('/wishlist', verifyJWT, async (req, res) => {
            const item = req.body;
            // Check duplicate
            const exists = await wishlistCollection.findOne({
                userEmail: item.userEmail,
                serviceId: item.serviceId
            });
            if (exists) {
                return res.send({ message: 'Already in wishlist', insertedId: null });
            }
            const result = await wishlistCollection.insertOne(item);
            res.send(result);
        });

        // Get User Wishlist
        app.get('/wishlist', verifyJWT, async (req, res) => {
            const email = req.decoded_email;
            const result = await wishlistCollection.find({ userEmail: email }).toArray();
            res.send(result);
        });

        // Remove from Wishlist
        app.delete('/wishlist/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const result = await wishlistCollection.deleteOne({ _id: new ObjectId(id) });
            res.send(result);
        });

        // ===========================================
        // REVIEWS ENDPOINTS
        // ===========================================
        // Add Review
        app.post('/reviews', verifyJWT, async (req, res) => {
            const review = req.body;
            review.createdAt = new Date();
            const result = await reviewsCollection.insertOne(review);
            res.send(result);
        });

        // Get Reviews for a Service
        app.get('/reviews/:serviceId', async (req, res) => {
            const serviceId = req.params.serviceId;
            const result = await reviewsCollection.find({ serviceId: serviceId }).sort({ createdAt: -1 }).toArray();
            res.send(result);
        });

        // ===========================================
        // CHAT / MESSAGING ENDPOINTS
        // ===========================================

        // Send a Message
        app.post('/messages', verifyJWT, async (req, res) => {
            const message = req.body;
            message.createdAt = new Date();
            message.read = false; // Set initial read status
            const result = await messagesCollection.insertOne(message);
            res.send(result);
        });

        // Get Messages for a Booking
        app.get('/messages/:bookingId', verifyJWT, async (req, res) => {
            const bookingId = req.params.bookingId;
            const result = await messagesCollection.find({ bookingId: bookingId }).sort({ createdAt: 1 }).toArray();
            res.send(result);
        });

        // Mark Messages as Read
        app.patch('/messages/mark-read/:bookingId', verifyJWT, async (req, res) => {
            const bookingId = req.params.bookingId;
            const userEmail = req.decoded_email;

            // Mark all messages in this booking NOT sent by me as read
            const filter = {
                bookingId: bookingId,
                senderEmail: { $ne: userEmail },
                read: false
            };

            const updateDoc = {
                $set: { read: true }
            };

            const result = await messagesCollection.updateMany(filter, updateDoc);
            res.send(result);
        });

        // ===========================================
        // PORTFOLIO ENDPOINTS
        // ===========================================
        // Create Portfolio Item
        app.post('/portfolios', verifyJWT, async (req, res) => {
            const item = req.body;
            item.createdAt = new Date();
            // Ensure decorator email is attached securely
            item.decoratorEmail = req.decoded_email;

            const result = await portfoliosCollection.insertOne(item);
            res.send(result);
        });

        // Get All Portfolios (Public)
        app.get('/portfolios', async (req, res) => {
            const result = await portfoliosCollection.find().sort({ createdAt: -1 }).toArray();
            res.send(result);
        });

        // Get My Portfolio (Decorator)
        app.get('/portfolios/my-portfolio', verifyJWT, async (req, res) => {
            const email = req.decoded_email;
            const result = await portfoliosCollection.find({ decoratorEmail: email }).sort({ createdAt: -1 }).toArray();
            res.send(result);
        });




        // Firebase login: client posts idToken; server verifies
        // RESPONSE: Returns accessToken and refreshToken in JSON 
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

                // store refresh token in DB (for revocation)
                await usersCollection.updateOne({ email }, { $set: { refreshToken } });

                // Respond with tokens in JSON
                return res.json({
                    message: 'Login successful',
                    role: user.role,
                    accessToken,
                    refreshToken
                });
            } catch (err) {
                console.error('firebase-login error:', err);
                return res.status(401).send({ message: 'Invalid Firebase token' });
            }
        });

        // Refresh endpoint
        // REQUEST: { refreshToken: "..." }
        // RESPONSE: { accessToken: "..." }
        app.post('/auth/refresh-token', async (req, res) => {
            try {
                const { refreshToken } = req.body;
                if (!refreshToken) return res.status(401).send({ message: 'No refresh token provided' });

                const user = await usersCollection.findOne({ refreshToken });
                if (!user) return res.status(403).send({ message: 'Invalid refresh token' });

                jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
                    if (err) return res.status(403).send({ message: 'Invalid refresh token' });

                    const newAccessToken = generateAccessToken({ email: decoded.email, role: user.role });

                    return res.json({ message: 'Access token refreshed', accessToken: newAccessToken });
                });
            } catch (err) {
                console.error('refresh-token error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // Logout
        app.post('/auth/logout', async (req, res) => {
            try {
                return res.json({ message: 'Logged out' });
            } catch (err) {
                console.error('logout error:', err);
                return res.status(500).send({ message: 'Server error' });
            }
        });

        // Get current user profile
        app.get('/users/me', verifyJWT, async (req, res) => {
            try {
                const email = req.decoded_email;
                let user = await usersCollection.findOne({ email }, { projection: { refreshToken: 0 } });
                if (!user) return res.status(404).send({ message: 'User not found' });


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

        // Example admin route
        app.get('/admin/data', verifyJWT, verifyAdmin, async (req, res) => {
            return res.json({ message: 'admin only data' });
        });


        // (Optional) legacy users creation route (kept for compatibility)
        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = 'user';
            user.createdAt = new Date();

            // Generate unique referral code for the new user
            user.referralCode = Math.random().toString(36).substring(2, 8).toUpperCase();
            user.referralRewards = [];

            const existing = await usersCollection.findOne({ email: user.email });
            if (existing) return res.send({ message: 'user already exist' });

            // Application of Referral Logic
            if (user.referralCodeInput) {
                const referrer = await usersCollection.findOne({ referralCode: user.referralCodeInput });
                if (referrer) {
                    user.referredBy = referrer.email;

                    // Reward Referrer (10% OFF Coupon)
                    const reward = {
                        id: new ObjectId(),
                        type: 'coupon',
                        code: `REF-${Math.floor(1000 + Math.random() * 9000)}`,
                        discount: 10,
                        description: 'Referral Bonus: 10% OFF',
                        createdAt: new Date(),
                        isUsed: false
                    };

                    await usersCollection.updateOne(
                        { email: referrer.email },
                        { $push: { referralRewards: reward } }
                    );
                }
            }

            // Remove the input field from the saved object
            delete user.referralCodeInput;

            const result = await usersCollection.insertOne(user);
            res.json(result);
        });

        //  services related apis

        // get all the services
        app.get('/services', async (req, res) => {
            try {
                const { search, sort, category } = req.query;
                const page = parseInt(req.query.page) || 0;
                const limit = parseInt(req.query.limit) || 12; // default 12 as requested
                const skip = page * limit;

                let query = {};

                // Search by title
                if (search) {
                    query.title = { $regex: search, $options: 'i' };
                }

                // Filter by category
                if (category && category !== 'all') {
                    query.category = category;
                }

                // Price Range Filter
                const { min, max } = req.query;
                if (min || max) {
                    query.price = {};
                    if (min) query.price.$gte = parseFloat(min);
                    if (max) query.price.$lte = parseFloat(max);
                }


                // Get total count for pagination
                const total = await servicesCollection.countDocuments(query);

                let cursor = servicesCollection.find(query);

                // Sorting
                if (sort === 'price-asc') {
                    cursor = cursor.sort({ price: 1 });
                } else if (sort === 'price-desc') {
                    cursor = cursor.sort({ price: -1 });
                } else if (sort === 'newest') {
                    cursor = cursor.sort({ createdAt: -1 });
                }

                const result = await cursor.skip(skip).limit(limit).toArray();

                res.send({
                    success: true,
                    count: result.length,
                    total,   // Total matching documents
                    page,
                    limit,
                    data: result
                });

            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });


        // Get all unique categories with counts
        app.get('/services/categories', async (req, res) => {
            try {
                const categories = await servicesCollection.aggregate([
                    {
                        $group: {
                            _id: "$category",
                            count: { $sum: 1 }
                        }
                    },
                    {
                        $project: {
                            category: "$_id",
                            count: 1,
                            _id: 0
                        }
                    },
                    {
                        $sort: { category: 1 }
                    }
                ]).toArray();

                res.send(categories);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });


        //  Get Single service by id for details:
        app.get('/services/:id', async (req, res) => {
            try {
                const id = req.params.id;

                const service = await servicesCollection.findOne({
                    _id: new ObjectId(id)
                });

                if (!service) {
                    return res.status(404).json({ success: false, message: "Service not found" });
                }

                res.status(200).json({
                    success: true,
                    data: service
                });

            } catch (error) {
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // ---------------------------------------------------------
        // USERS MANAGEMENT (Admin)
        // ---------------------------------------------------------

        // Get all users (Admin)
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        // Get decorators (Public or Admin)
        app.get('/decorators', async (req, res) => {
            const result = await usersCollection.find({ role: 'decorator' }).toArray();
            res.send(result);
        });

        // Update user role and status (Admin)
        app.patch('/users/role/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { role, status } = req.body;
            const filter = { _id: new ObjectId(id) };

            const updateFields = {};
            if (role) updateFields.role = role;
            if (status) updateFields.status = status;

            const updateDoc = {
                $set: updateFields
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // Delete user (Admin)
        app.delete('/users/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await usersCollection.deleteOne(query);
            res.send(result);
        });

        // ---------------------------------------------------------
        // APPLICATIONS (Become Decorator)
        // ---------------------------------------------------------

        app.post('/applications', verifyJWT, async (req, res) => {
            const application = req.body;

            // Check if already applied
            const existingApplication = await usersCollection.findOne({ email: application.email, status: 'requested' });
            if (existingApplication) {
                return res.send({ message: 'Already applied' });
            }


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

        // ---------------------------------------------------------
        // SERVICES MANAGEMENT (Admin)
        // ---------------------------------------------------------

        // Add a service
        app.post('/services', verifyJWT, verifyAdmin, async (req, res) => {
            const service = req.body;
            const result = await servicesCollection.insertOne(service);
            res.send(result);
        });

        // Delete a service
        app.delete('/services/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await servicesCollection.deleteOne(query);
            res.send(result);
        });

        // Update a service
        app.patch('/services/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedService = req.body;
            const updateDoc = {
                $set: {
                    ...updatedService
                }
            };
            const result = await servicesCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // ---------------------------------------------------------
        // BOOKINGS API
        // ---------------------------------------------------------

        // Create booking (User)
        app.post('/bookings', verifyJWT, async (req, res) => {
            const booking = req.body;
            booking.createdAt = new Date();
            booking.status = 'pending';
            const result = await bookingsCollection.insertOne(booking);
            res.send(result);
        });

        // Get bookings (Admin: all, User: mine, Decorator: assigned)
        app.get('/bookings', verifyJWT, async (req, res) => {
            const role = req.decoded_role;
            const email = req.decoded_email;
            const page = parseInt(req.query.page) || 0;
            const limit = parseInt(req.query.limit) || 10;
            const skip = page * limit;

            let query = {};
            if (role === 'user') {
                query = { userEmail: email };
            } else if (role === 'decorator') {
                query = { decoratorEmail: email };
            }

            console.log(`API: Get Bookings - Role: ${role}, Email: ${email}`);

            let result = await bookingsCollection.find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .toArray();

            // Calculate Unread Messages for each booking
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

            res.send({
                data: result,
                total,
                limit,
                page
            });
        });

        // Cancel Booking (User - only 'pending')
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

        // Update booking status/assign decorator (Admin/Decorator)
        app.patch('/bookings/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const { status, decoratorEmail } = req.body;
            const filter = { _id: new ObjectId(id) };

            let updateDoc = {
                $set: {}
            };
            if (status) updateDoc.$set.status = status;
            if (decoratorEmail) updateDoc.$set.decoratorEmail = decoratorEmail;

            const result = await bookingsCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // Get Single Booking
        app.get('/bookings/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            console.log("API: Fetching booking ID:", id);
            const query = { _id: new ObjectId(id) };
            const result = await bookingsCollection.findOne(query);
            console.log("API: Found booking:", result);
            res.send(result);
        });

        // ---------------------------------------------------------
        // PAYMENTS
        // ---------------------------------------------------------


        // Create Payment Intent
        app.post('/create-payment-intent', verifyJWT, async (req, res) => {
            try {
                const { price } = req.body;
                if (!price || isNaN(price)) {
                    return res.status(400).send({ message: 'Invalid price' });
                }
                const amount = Math.round(Number(price) * 100);

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amount,
                    currency: 'usd',
                    automatic_payment_methods: {
                        enabled: true,
                    },
                });

                res.send({
                    clientSecret: paymentIntent.client_secret
                });
            } catch (error) {
                console.error("Error creating payment intent:", error);
                res.status(500).send({ message: error.message });
            }
        });


        app.post('/payment-checkout-session', async (req, res) => {
            const paymentInfo = req.body;

            // Use parseFloat to handle number/numeric string, and Math.round for cents conversion
            const costInDollars = parseFloat(paymentInfo.cost);

            if (isNaN(costInDollars) || costInDollars <= 0) {
                return res.status(400).send({ message: 'Invalid or missing cost parameter.' });
            }

            const amount = Math.round(costInDollars * 100);

            const session = await stripe.checkout.sessions.create({
                line_items: [
                    {
                        price_data: {
                            currency: 'usd',
                            unit_amount: amount,
                            product_data: {
                                name: `Paying for: ${paymentInfo.parcelName}`,
                            }
                        },
                        quantity: 1,
                    },
                ],
                customer_email: paymentInfo.senderEmail,
                mode: 'payment',
                metadata: {
                    bookingId: paymentInfo.bookingId, // Changed from parcelId
                    parcelId: paymentInfo.parcelId,
                    parcelName: paymentInfo.parcelName
                },
                success_url: `${process.env.CLIENT_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_URL}/dashboard/payment-canceled`,
            })
            res.send({ url: session.url })
        })

        // Payment Success to save into database
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
                        bookingId: session.metadata.bookingId, // Capture bookingId
                        parcelId: session.metadata.parcelId,
                        status: 'paid',
                        parcelName: session.metadata.parcelName
                    }

                    const result = await paymentsCollection.insertOne(payment);

                    // Update Booking Status to 'paid'
                    const bookingId = session.metadata.bookingId;
                    if (bookingId) {
                        const filter = { _id: new ObjectId(bookingId) };
                        const updateDoc = {
                            $set: {
                                status: 'paid'
                            }
                        };
                        await bookingsCollection.updateOne(filter, updateDoc);
                    }

                    res.send({
                        success: true,
                        transactionId: payment.transactionId,
                        trackingId: result.insertedId
                    });
                } else {
                    res.status(400).send({ message: 'Payment not paid' });
                }

            } catch (error) {
                console.error("Error verifying payment:", error);
                res.status(500).send({ message: error.message });
            }
        });


        // Save Payment Info
        app.post('/payments', verifyJWT, async (req, res) => {
            const payment = req.body;
            const paymentResult = await paymentsCollection.insertOne(payment);

            // carefully delete each item from the cart
            const query = {
                _id: {
                    $in: payment.bookingIds.map(id => new ObjectId(id))
                }
            };

            const updatedDoc = {
                $set: {
                    status: 'paid'
                }
            }

            const updatedResult = await bookingsCollection.updateMany(query, updatedDoc);

            res.send({ paymentResult, updatedResult });
        });

        // Get Payment History
        app.get('/payments/:email', verifyJWT, async (req, res) => {
            const query = { email: req.params.email };
            const result = await paymentsCollection.find(query).toArray();
            res.send(result);
        });

        // ---------------------------------------------------------
        // DECORATOR FEATURES
        // ---------------------------------------------------------

        // Submit Application
        app.post('/applications', async (req, res) => {
            try {
                const application = req.body;
                application.createdAt = new Date();
                application.status = 'pending';
                // Check if already applied
                const existing = await applicationsCollection.findOne({ email: application.email });
                if (existing) {
                    return res.send({ message: 'Already applied', insertedId: null });
                }
                const result = await applicationsCollection.insertOne(application);
                res.send(result);
            } catch (error) {
                console.error("Error submitting application:", error);
                res.status(500).send({ message: 'Server error' });
            }
        });

        // Get Decorator Stats
        app.get('/decorator/stats', verifyJWT, async (req, res) => {
            const email = req.decoded_email;
            const role = req.decoded_role;

            if (role !== 'decorator') {
                return res.status(403).send({ message: 'Forbidden access' });
            }

            try {

                const stats = await bookingsCollection.aggregate([
                    {
                        $match: {
                            decoratorEmail: email,
                            status: { $in: ['paid', 'completed', 'in-progress'] } // active/paid bookings
                        }
                    },
                    {
                        $group: {
                            _id: null,
                            totalBookings: { $sum: 1 },
                            totalEarnings: { $sum: { $toDouble: "$price" } }, // Ensure price is number
                            completedBookings: {
                                $sum: {
                                    $cond: [{ $eq: ["$status", "completed"] }, 1, 0]
                                }
                            }
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

        // ---------------------------------------------------------
        // ANALYTICS (Admin)
        // ---------------------------------------------------------
        app.get('/admin/stats', verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const users = await usersCollection.estimatedDocumentCount();
                const products = await servicesCollection.estimatedDocumentCount();
                const bookings = await bookingsCollection.estimatedDocumentCount();

                const payments = await bookingsCollection.aggregate([
                    {
                        $group: {
                            _id: null,
                            totalRevenue: { $sum: { $toDouble: "$price" } }
                        }
                    }
                ]).toArray();

                const revenue = payments.length > 0 ? payments[0].totalRevenue : 0;

                res.send({
                    users,
                    products,
                    bookings,
                    revenue
                });
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // --- PUBLIC ENDPOINTS FOR HOME PAGE ---

        // Get public stats (Home page)
        app.get('/public-stats', async (req, res) => {
            try {
                const totalUsers = await usersCollection.estimatedDocumentCount();
                const totalServices = await servicesCollection.estimatedDocumentCount();
                const totalBookings = await bookingsCollection.estimatedDocumentCount();
                const totalDecorators = await usersCollection.countDocuments({ role: 'decorator' });

                // Assuming "Projects Completed" means completed bookings
                const completedProjects = await bookingsCollection.countDocuments({ status: 'completed' });

                res.send({
                    totalUsers,
                    totalServices,
                    totalBookings,
                    totalDecorators,
                    completedProjects: completedProjects + 1200, // Adding historical data to live count
                    expertDecorators: totalDecorators + 15, // Adding historical/partner decorators
                    satisfaction: 98, // Static brand promise
                    yearsExperience: 10 // Production value
                });
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        // Get featured reviews (Home page)
        app.get('/featured-reviews', async (req, res) => {
            try {
                const reviews = await reviewsCollection.aggregate([
                    { $match: { rating: { $gte: 4 } } },
                    { $sort: { createdAt: -1 } },
                    { $limit: 6 },
                    {
                        $lookup: {
                            from: 'users',
                            localField: 'userEmail',
                            foreignField: 'email',
                            as: 'userDetails'
                        }
                    },
                    {
                        $unwind: {
                            path: '$userDetails',
                            preserveNullAndEmptyArrays: true
                        }
                    },
                    {
                        $project: {
                            userName: 1,
                            comment: 1,
                            rating: 1,
                            createdAt: 1,
                            userPhoto: '$userDetails.photoURL'
                        }
                    }
                ]).toArray();
                res.send(reviews);
            } catch (error) {
                res.status(500).send({ message: 'Server error', error });
            }
        });

        app.listen(port, () => console.log(`Server running on port ${port}`));

    } catch (error) {
        console.error("Error in run:", error);
    } finally {
        // keep DB connection open
    }
}
run().catch(console.dir);
