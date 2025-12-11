# StyleDecor Server

## Purpose
StyleDecor Server is the backend API that powers the StyleDecor application. It handles data persistence, user authentication verification, payment processing, and administrative logic. It serves as the bridge between the client application and the MongoDB database.

## Live URL
[Insert Live URL Here]

## Key Features
- **RESTful API**: Endpoints for users, services, bookings, and payments.
- **Database Management**: Integration with simple MongoDB operations for data storage.
- **Authentication**: JWT (JSON Web Token) generation and verification for secure API access.
- **Payment Processing**: Stripe backend integration for creating payment intents.
- **Role-Based Security**: Middleware to verify user roles (Admin, Decorator, User) before allowing sensitive actions.
- **Cookies Management**: Secure handling of authentication tokens via cookies.

## NPM Packages Used
- **cookie-parser**: ^1.4.7
- **cors**: ^2.8.5
- **dotenv**: ^17.2.3
- **express**: ^5.2.1
- **firebase-admin**: ^13.6.0
- **jsonwebtoken**: ^9.0.3
- **mongodb**: ^7.0.0
- **stripe**: ^20.0.0
