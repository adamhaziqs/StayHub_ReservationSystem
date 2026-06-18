# MyApp - Authentication, RBAC, Task Management, and Audit Logs

This Node.js application now includes:
- Local user registration and login
- Role-based access control (admin and normal user)
- Task management CRUD module
- User profile page
- Audit log page showing login attempts and system events
- Optional Google OAuth login when credentials are provided

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file if you want to enable Google login:
   ```ini
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   SESSION_SECRET=your-session-secret
   ADMIN_PASSWORD=Admin123!
   ```

3. Run the app:
   ```
   npm start
   ```

4. Open your browser to `http://localhost:3000`

## Default Admin Account

A default admin user is seeded on first run.
- Email: `admin@example.com`
- Password: `Admin123!`

You can change the default admin password with the `ADMIN_PASSWORD` environment variable.

## Usage

- Register as a normal user at `/register`
- Login at `/login`
- View your dashboard at `/`
- Manage tasks at `/tasks`
- View your profile at `/profile`
- Admin users can view the audit log at `/audit`

## Notes

- User data is stored in `data.json`.
- Passwords are hashed using PBKDF2.
- Google login is only available if `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set.
- This project is intended as an educational demo and should be hardened before production use.
