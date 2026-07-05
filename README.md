# JWT Authentication System with Refresh Token Rotation

A production-inspired authentication system built using **Node.js**, **Express.js**, **MongoDB**, and **Mongoose** that implements secure JWT authentication with refresh token rotation, device-aware session management, and protection against common authentication vulnerabilities and race conditions.

The project focuses on building an authentication system that is not only secure, but also remains **consistent under concurrent requests** by leveraging MongoDB transactions, atomic operations, and database-level constraints.

---

## Features

- User registration with secure password hashing using bcrypt
- Login using either username or email
- JWT-based authentication
- Short-lived Access Tokens
- HttpOnly Refresh Token Cookies
- Refresh Token Rotation
- SHA-256 hashing of Refresh Tokens before database storage
- Device-aware session management
- Maximum of 3 active devices per user
- Automatic replacement of existing session on the same device
- Refresh Token reuse detection
- Automatic revocation of compromised sessions
- Role-based authorization support
- MongoDB Transactions
- Atomic database updates
- Partial Unique Indexes
- TTL Indexes for automatic cleanup of expired refresh tokens

---

# Authentication Flow

## User Registration

- Creates a new user account.
- Passwords are automatically hashed using bcrypt before storage.
- Unique indexes prevent duplicate usernames and email addresses.

---

## Login

The login endpoint performs the following operations inside a MongoDB transaction:

1. Authenticate user credentials.
2. Revoke any active session currently associated with the device.
3. Decrement the previous user's active session count.
4. Atomically reserve one available device slot for the new user.
5. Generate a cryptographically secure refresh token.
6. Store only the SHA-256 hash of the refresh token.
7. Generate a short-lived JWT Access Token.
8. Return the Refresh Token as an HttpOnly cookie.

---

## Refresh Session

The refresh endpoint implements **Refresh Token Rotation**.

Every successful refresh request:

- Atomically revokes the previous refresh token.
- Generates a new refresh token.
- Issues a new JWT access token.
- Invalidates the previously used refresh token.

This prevents replay attacks using previously issued refresh tokens.

---

## Logout

Logout is also performed transactionally.

The endpoint:

- Revokes the current refresh token.
- Updates the user's active session count.
- Clears the refresh token cookie.

---

# Session Management

Each browser/device is identified using a persistent **Device ID**.

Only one active authenticated session may exist on a device.

If another user logs in using the same browser:

- the previous user's refresh token is revoked,
- the previous user's active session count is updated,
- the new user becomes the active owner of the device.

---

# Refresh Token Storage

Refresh Tokens are **never stored in plaintext**.

Each token is hashed using SHA-256 before being persisted.

Even if the database is compromised, attackers cannot directly use stored refresh tokens.

---

# Security Features

- JWT Authentication
- HttpOnly Refresh Token Cookies
- Refresh Token Rotation
- Refresh Token Hashing
- Device-aware Authentication
- Maximum Active Device Limit
- Refresh Token Reuse Detection
- Automatic Session Revocation
- Password Hashing using bcrypt
- MongoDB Transactions
- Atomic Database Operations
- Partial Unique Indexes
- TTL Indexes

---

# Concurrency Engineering Challenges Solved

Designing an authentication system involves more than verifying credentials. Since multiple requests can arrive concurrently from different devices, browser tabs, or network retries, several race conditions can leave the database in an inconsistent state.

This authentication system was designed to handle these scenarios using **atomic database operations**, **MongoDB transactions**, and **database-enforced constraints**.

---

## Atomic Device Slot Reservation

A naive login implementation performs the following sequence:

```
Read activeSessions

↓

Check activeSessions < 3

↓

Increment activeSessions

↓

Create Refresh Token
```

Two concurrent login requests can both observe the same session count and exceed the configured device limit.

To eliminate this race condition, session reservation is performed using an atomic conditional update:

```javascript
updateOne(
    {
        _id: userId,
        activeSessions: { $lt: 3 }
    },
    {
        $inc: {
            activeSessions: 1
        }
    }
)
```

MongoDB guarantees that only one request can reserve the final available session slot.

---

## Transactional Login

A successful login modifies multiple pieces of state simultaneously:

- revoke any active session associated with the current device,
- update the previous user's active session count,
- reserve a session for the new user,
- create a new refresh token.

If one operation succeeds while another fails, the authentication state becomes inconsistent.

All login operations are therefore executed inside a MongoDB transaction, ensuring that either every modification is committed or none of them are.

---

## Device Session Replacement

A browser profile is treated as a single authenticated device.

Whenever another user logs in from the same device:

- the previous refresh token is revoked,
- the previous owner's session count is decremented,
- the new session is created.

Performing these operations inside a transaction prevents partially completed session transfers.

---

## Refresh Token Rotation Without Branching

A common race condition occurs when two refresh requests simultaneously attempt to rotate the same refresh token.

Without synchronization:

```
Request A
↓

Creates Token B

Request B
↓

Creates Token C
```

Both newly generated refresh tokens become valid, creating multiple descendants from a single refresh token.

To prevent this, refresh tokens are **claimed atomically** using:

```javascript
findOneAndUpdate(
    {
        tokenHash,
        revoked: false
    },
    {
        $set: {
            revoked: true
        }
    }
)
```

Only one request can successfully revoke and replace the refresh token. Any concurrent request attempting to use the same token is treated as token reuse.

---

## Refresh Token Reuse Detection

If a refresh token that has already been rotated or revoked is presented again, it may indicate token theft or replay.

Instead of silently rejecting the request, the system:

- detects refresh token reuse,
- revokes every active refresh token belonging to the user,
- invalidates all active sessions,
- forces the user to authenticate again.

This minimizes the impact of refresh token compromise.

---

## Database-Level Session Invariants

Application-level validation alone cannot guarantee correctness under concurrent requests.

Critical invariants are enforced directly by MongoDB using indexes:

- Unique indexes prevent duplicate refresh tokens.
- Partial Unique Indexes ensure only one active session exists per device.
- TTL Indexes automatically remove expired refresh tokens.

Database-level constraints prevent invalid authentication states from being committed even under concurrent access.

---

## Concurrent Logout Safety

Duplicate logout requests may occur due to browser retries, multiple tabs, or repeated API calls.

Logout uses an atomic conditional update that revokes only active refresh tokens.

Only the first logout request decrements the user's active session count.

Subsequent requests become no-ops, preventing incorrect negative session counts.

---

## Consistent Derived State

The system maintains an `activeSessions` counter to efficiently enforce the maximum device limit.

Since this value is derived from active refresh tokens, every operation that changes authentication state—including login, logout, device replacement, and refresh token reuse detection—updates both the Refresh Token collection and the User document within the same MongoDB transaction.

This guarantees that session counts remain consistent even if failures occur midway through an operation.

---

# Database Design

## User

```
User
├── name
├── username
├── email
├── password (bcrypt hash)
├── role
├── activeSessions
├── createdAt
└── updatedAt
```

---

## RefreshToken

```
RefreshToken
├── tokenHash (SHA-256)
├── userId
├── deviceId
├── revoked
├── expiresAt
├── absoluteExpiresAt
├── createdAt
└── updatedAt
```

---

# Tech Stack

- Node.js
- Express.js
- MongoDB
- Mongoose
- JWT
- bcrypt
- crypto
- Cookie Parser

---

# Future Improvements

- Device fingerprinting instead of client-generated device identifiers
- Email verification
- Password reset flow
- Multi-factor Authentication (MFA)
- Rate limiting for authentication endpoints
- Audit logs for authentication events
- OAuth providers (Google/GitHub)
- Redis-backed session caching
- Role & Permission based Access Control (RBAC)

---

## Learning Outcomes

This project was built to gain a deeper understanding of production authentication systems and distributed state consistency. It explores concepts such as:

- JWT Authentication
- Refresh Token Rotation
- Session Management
- Secure Password Storage
- MongoDB Transactions
- Atomic Database Operations
- Database Indexing Strategies
- Race Condition Prevention
- Concurrency Control
- Database Consistency
- Authentication Security Best Practices
