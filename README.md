# 4 Messenger Server

![4 Messenger](https://img.shields.io/badge/4-Messenger-4F46E5?style=for-the-badge)

## Features

- 🔒 **AES-256-GCM encryption** - Messages are encrypted
- 👥 **Group chats** - Create groups with admin controls
- 📞 **Voice & Video Calls** - WebRTC-based calling (not working)
- 📎 **File Sharing** - Upload and share files
- 👤 **Role System** - Admin, Moderator, User, Banned
- 🛡️ **Admin Panel** - Server management dashboard
- ✉️ **Email Verification** - Optional email verification
- 🔑 **Server Password** - Password-protect your server
- 🤖 **CAPTCHA** - Bot protection
- 💾 **SQLite Database** - Zero-config database
- 🔐 **JWT Authentication** - Token-based auth

## Quick Start

```bash
cd server
npm install
npm start
```


## Configuration

Edit `server/config.json` to customize:
- Server password
- Email verification (SMTP settings)
- CAPTCHA on/off
- File upload limits
- Encryption settings
- Default admin credentials

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login
- `POST /api/logout` - Logout
- `GET /api/me` - Get current user
- `GET /api/verify-email?token=...` - Verify email

### Server
- `GET /api/server-info` - Get server configuration
- `POST /api/verify-password` - Verify server password
- `GET /api/captcha` - Get CAPTCHA challenge
- `POST /api/captcha/verify` - Verify CAPTCHA answer

### Users
- `GET /api/users` - List all users
- `PUT /api/users/:id/role` - Update user role (admin)
- `POST /api/users/:id/ban` - Ban user (mod+)
- `POST /api/users/:id/unban` - Unban user (mod+)
- `DELETE /api/users/:id` - Delete user (admin)

### Chats
- `GET /api/chats` - Get user's chats
- `POST /api/chats/direct` - Create direct chat
- `POST /api/chats/group` - Create group chat
- `POST /api/chats/:id/members` - Add member
- `DELETE /api/chats/:id/members/:userId` - Remove member
- `POST /api/chats/:id/leave` - Leave group

### Messages
- `GET /api/chats/:id/messages` - Get messages
- `POST /api/chats/:id/messages` - Send message
- `PUT /api/messages/:id` - Edit message
- `DELETE /api/messages/:id` - Delete message

### Files
- `POST /api/upload` - Upload file

### Admin
- `GET /api/admin/stats` - Dashboard statistics
- `GET /api/admin/config` - Get server config
- `PUT /api/admin/config` - Update server config

## Tech Stack

- Node.js + Express
- SQLite (sql.js)
- JWT authentication
- bcryptjs (password hashing)
- AES-256-GCM encryption

## License

MIT
