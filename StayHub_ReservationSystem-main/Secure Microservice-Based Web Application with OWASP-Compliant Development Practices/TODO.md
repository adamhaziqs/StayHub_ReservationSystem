# TODO - Admin password change

- [ ] Generate a strong new admin password
- [ ] Set `ADMIN_PASSWORD` for the server process (recommended via `.env`):
  - `ADMIN_PASSWORD=YourNewStrongPasswordHere`
- [ ] Reseed the admin by removing the current admin from `data.json`:
  - Open `data.json`
  - Remove any user objects with `role: "admin"`
  - Save the file
- [ ] Restart the server and verify admin login works:
  - Visit `http://localhost:<PORT>/admin/login`
  - Log in with the new admin password

Notes:
- On startup, if `data.json` does not contain an admin user (`role: "admin"`), the server will recreate the default admin using the current `ADMIN_PASSWORD`.
- Do not commit `.env` secrets to version control.
