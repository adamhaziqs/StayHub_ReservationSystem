# Source Code Submission Checklist

This checklist describes the artifacts included in the source-code submission and quick verification steps.

- [x] Project folder: `Secure Microservice-Based Web Application with OWASP-Compliant Development Practices`
- [x] Install & run instructions: `README.md` (updated)
- [x] `.env.example` included (no real secrets)
- [x] Dependency list present (see `package.json` and `README.md`)
- [x] Data files required for demo: `data.json` (included in project folder)
- [x] No website/application code was modified beyond documentation and example env file

Verification steps:

1. Install dependencies:

```bash
npm install
```

2. Copy the example env file and edit values as needed:

```bash
cp "Secure Microservice-Based Web Application with OWASP-Compliant Development Practices/.env.example" "Secure Microservice-Based Web Application with OWASP-Compliant Development Practices/.env"
```

3. Start the server from the project folder:

```bash
cd "Secure Microservice-Based Web Application with OWASP-Compliant Development Practices"
npm start
```

4. Open `http://localhost:3000` in your browser.

Archive produced: `submission.zip` (contains the project folder)

Notes:
- This checklist and the `.env.example` were added for submission packaging only. No runtime code or website behaviour was changed.
