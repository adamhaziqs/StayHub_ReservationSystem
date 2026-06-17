# StayHub_ReservationSystem

This repository contains the documentation, system architecture configuration, and user guides for **StayHub_ReservationSystem**, a secure Node.js-based web application tailored for managing accommodations, user bookings, and administrative operations.

---

## 1. Project Description

**StayHub_ReservationSystem** is a full-stack web application built using Node.js and the Express framework. The platform provides a secure environment for guests to browse and book vacation properties while offering an administrative control tier for system-wide oversight.

### Key Modules Implemented
* **Guest Reservation Management:** Allows registered users to look up properties, select operational check-in/check-out dates, specify guest counts, view total calculated costs, and track booking states like *Confirmed* or *Active*.
* **Property Management Engine:** An isolated administrative dashboard interface enabling authorized personnel to dynamically add, edit, and delete available accommodations, tracking data metrics such as location and price per night.
* **Security & System Audit Logging:** A transparent backend tracing ledger that continuously records system events chronologically, capturing action types (`login success`, `booking created`), message confirmation details, user hashes, timestamps, and client IP addresses.

---

## 2. System Requirements

### 2.1 Environment & Software Runtime
| Requirement | Minimum Supported Version / Value | Purpose |
| :--- | :--- | :--- |
| **Node.js** | `>= 18.0` (LTS Recommended) | Core JavaScript runtime environment |
| **npm** | `>= 9.0` | Package manager for dependency handling |
| **Operating System** | Windows 10/11, macOS (Monterey+), or Linux | Host deployment environment |

### 2.2 Application Environment Variables (`.env`)
| Variable Key | Required Status | Accepted Values / Description |
| :--- | :--- | :--- |
| **`PORT`** | Optional | Default is `3000` (or any available network port) |
| **`NODE_ENV`** | Required | `development` \| `production` |
| **`SESSION_SECRET`** | **Required** | Secure, random string (min 32 characters) to sign cookies |
| **`ADMIN_PASSWORD`** | **Required** | Initial credential key for root administrative access |
| **`GOOGLE_CLIENT_ID`** | Optional | Credentials required if enabling Google OAuth integration |
| **`GOOGLE_CLIENT_SECRET`**| Optional | Credentials required if enabling Google OAuth integration |

---

## 3. Installation Steps

Follow these steps to set up the development environment on your local machine.

### Step-by-Step Setup

1. **Clone or Extract the Project Directory**
   Ensure all project files, including `package.json` and configuration templates, are placed in your working directory.

2. **Install Dependencies**
   Open your terminal (e.g., PowerShell) in the project root folder and execute the following command to download and install all required node modules:
   ```powershell
   npm install


3. **Configure Environment Variables**
The application relies on environment files to protect sensitive keys. Duplicate the provided example configuration file:
```powershell

cp .env.example .env

```

Open the newly created `.env` file and populate the necessary variable values based on the requirements table in Section 2.2.

---

## 4. Security Features Summary

To ensure user data integrity and defense against common web vulnerabilities, the system implements the following security controls:

* **Authentication & Federated Identity:** Handled via Passport.js, enabling robust local credential validation alongside secure, token-based **Google OAuth 2.0** social logins to prevent password-fatigue risks. Separate routing paths isolate standard Guest cards from Administrative logins.
* **Cryptographic Hashing & PII Redaction:** To preserve privacy in public logging grids, sensitive user data identifiers (such as guest email strings) are explicitly redacted (`[REDACTED_EMAIL]`) or replaced with secure tracking hashes.
* **Comprehensive Security Audit Logging:** Features a read-only tracking system console accessible by administrators to log chronological milestones, mapping precise timestamps, connection IP footprints (`::1`), verification classifications, and system workflow strings.
* **Secure Session Management:** Utilizes `express-session` to maintain stateful client interactions safely, ensuring session identifiers are cryptographically signed using a server-side hidden secret.
* **Environment Hardening & Secret Isolation:** Implements `dotenv` to abstract all sensitive components (API keys, ports, and admin strings) completely out of the static source code, preventing accidental credential exposure in version control.
* **Role-Based Authorization (RBAC):** Strict system walls programmatically distinguish between guest capabilities (creating reservations) and administrative execution permissions (managing properties, auditing security trails).

---

## 5. How to Run the App

Once the installation and configuration steps are finalized, you can initialize the server wrapper.

1. **Start the Application**
Run the pre-configured start script within your terminal:
```powershell
node server.js

```


2. **Access the Web Interface**
Open your web browser of choice and navigate to the local hosting address:
```http
http://localhost:3000

```


*(Note: If you specified a custom port variable in your `.env` file, replace `3000` with your designated port number).*

---

## 6. Dependencies

The application relies on a curated stack of production dependencies managed via the npm registry. Key frameworks and middleware libraries include:

| Dependency Name | Version | Primary Purpose within StayHub |
| --- | --- | --- |
| **`express`** | `>= 4.18` | Base web application framework and routing pipeline |
| **`express-session`** | `>= 1.17` | Server-side session state and client cookie management |
| **`passport`** | `>= 0.6` | Modular authentication framework ecosystem |
| **`passport-google-oauth20`** | `>= 2.0` | Passport strategy plugin enabling Google OAuth 2.0 logins |
| **`google-auth-library`** | `>= 8.0` | Google's officially supported library for token verification checks |
| **`dotenv`** | `>= 16.0` | Decouples production secrets from source code via `.env` |

---

## 7. Application Screenshots

### 7.1 LOGIN PAGE
<img width="1197" height="910" alt="Screenshot 2026-06-17 140240" src="https://github.com/user-attachments/assets/57cce9bd-f0f0-4089-a069-3a0cde3bfdba" />

### 7.2 Create Account
<img width="700" height="786" alt="Screenshot 2026-06-17 140357" src="https://github.com/user-attachments/assets/286208f8-0644-48d5-8de5-f8a86014977d" />

### 7.3 Customer Dashboard
<img width="1892" height="905" alt="Screenshot 2026-06-17 140259" src="https://github.com/user-attachments/assets/26d5b086-477e-419e-ac14-3ab447d4423e" />

### 7.4 Booking Form
<img width="1235" height="643" alt="Screenshot 2026-06-17 140416" src="https://github.com/user-attachments/assets/e094890c-bf06-4d68-a3bc-003d469a9cf8" />

### 7.5 Admin Dashboard
<img width="1902" height="908" alt="Screenshot 2026-06-17 142528" src="https://github.com/user-attachments/assets/72496c3d-9f91-41b3-91e2-db9852dfaf30" />

### 7.6 Guest Booking 
<img width="1652" height="483" alt="Screenshot 2026-06-17 140500" src="https://github.com/user-attachments/assets/abf7223e-d368-4ca6-aa1b-ffc0561c58c1" />

### 7.7 Audit Log
<img width="1665" height="895" alt="Screenshot 2026-06-17 140513" src="https://github.com/user-attachments/assets/b23a6a2c-b174-4aa9-a6c5-f95ce7bbff3e" />


---

Contributers:
- ADAM HAZIQ BIN DANIANTO
- MUHAMMAD ‘AZIM BIN HASHIM 
- MUHAMMAD HAKIMI BIN SAHUDI 



