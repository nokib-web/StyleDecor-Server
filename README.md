# ⚙️ StyleDecor Server — Robust Backend API

![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white) ![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge) ![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)

The **StyleDecor Server** is the powerhouse behind the StyleDecor platform. It provides a secure, RESTful API for handling user data, service management, real-time booking logic, and payment processing.

---

## 🔗 Live API Base URL
### `https://style-decor-server-mkbq.onrender.com`

---

## 🛠️ Technology Stack

*   **Runtime**: Node.js
*   **Framework**: Express.js
*   **Database**: MongoDB (Native Driver)
*   **Authentication**: Firebase Admin SDK & JWT (JSON Web Tokens)
*   **Payments**: Stripe API
*   **Security**: CORS, Cookie Parser, Environment Variables

---

## 🔑 Key Features

### 🛡️ Security & Authentication
*   **JWT Middleware**: Verifies client-side tokens via cookies to secure private routes.
*   **Role-Based Access Control (RBAC)**: Custom middleware (`verifyAdmin`, `verifyDecorator`) ensures restricted access for specific API endpoints.
*   **Firebase Integration**: Validates Firebase ID tokens for secure user creation and social login.

### 💳 Payment Processing
*   **Stripe Integration**: Generates `PaymentIntents` on the server side to securely handle transactions.
*   **Revenue Management**: Tracks earnings and calculates platform stats.

### 📝 Core Functionalities
*   **CRUD Operations**: Full management of Users, Services, Reviews, and Wishlists.
*   **Booking Management**: Complex logic for handling booking states, cancellations, and updates.
*   **Aggregation Pipelines**: Uses MongoDB aggregation to generate analytics data for the admin dashboard.

---

## 📦 API Endpoints Overview

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/jwt` | Generate JWT token | Public |
| `POST` | `/auth/logout` | Clear auth cookies | Public |
| `GET` | `/users` | Get all users | **Admin** |
| `POST` | `/bookings` | Create a new booking | **User** |
| `POST` | `/create-payment-intent` | Initiate Stripe payment | **User** |
| `GET` | `/admin-stats` | Get system analytics | **Admin** |

---

## 🚀 Getting Started Locally

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-username/style-decor-server.git
    cd style-decor-server
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Environment Setup**
    Create a `.env` file and add your secrets:
    ```env
    DB_USER=your_db_user
    DB_PASS=your_db_password
    ACCESS_TOKEN_SECRET=your_jwt_secret
    STRIPE_SECRET_KEY=your_stripe_secret_key
    ```

4.  **Run Server**
    ```bash
    npm start
    # or for development
    npm run dev
    ```
