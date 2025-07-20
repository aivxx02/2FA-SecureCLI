# 🔐 SecureCLI - Python CLI with 2FA (TOTP & Email)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-2FA%20Enabled-important)
![Supabase](https://img.shields.io/badge/Backend-Supabase-blue)

SecureCLI is a secure command-line interface (CLI) for user registration, login, and Two-Factor Authentication (2FA) using Google Authenticator, Microsoft Authenticator, or email OTP. This was built as part of my **cybersecurity portfolio** to demonstrate secure authentication practices and TOTP-based 2FA.

---

## 📌 Features

- 📝 **Secure Registration & Login**
  - Passwords hashed with `bcrypt`
  - Email validation with masking
  - CLI-friendly and color-coded UI

- 🔐 **Two-Factor Authentication**
  - Choose between:
    - 📱 Google Authenticator
    - 🔐 Microsoft Authenticator
    - ✉️ Email-based OTP
  - TOTP secret generation and QR code setup
  - Easily enable/disable 2FA anytime

- 🛠️ **User Account Management**
  - Change password and email
  - Full user settings
  - Password confirmation required for sensitive actions
  - Email masking for CLI output

- ☁️ **Supabase Integration**
  - Cloud-based storage of user accounts
  - PostgreSQL-backed and easy to set up

---

## ⚙️ Tech Stack

| Component        | Technology              |
|------------------|-------------------------|
| Language         | Python 3.10+            |
| Auth & 2FA       | `pyotp`, `qrcode`, `smtplib` |
| Password Hashing | `bcrypt`                |
| Backend          | [Supabase](https://supabase.com) |
| Email            | `EmailMessage`, Gmail SMTP |
| Config           | `dotenv` for `.env` secrets |

---

## 📷 Demo Screenshots

> - [Click here to View More Screenshots](screenshots/) <br />
<img src="screenshots/1 landing-page.png" alt="landingpage" width="300"/>
<img src="screenshots/2 register.png" alt="register" width="300"/>
<img src="screenshots/3 login.png" alt="login" width="300"/>
<img src="screenshots/4 user-homepage.png" alt="user-homepage" width="300"/>
<img src="screenshots/5 enable-2fa.png" alt="enable-2fa" width="300"/>
<img src="screenshots/6 disable-2fa.png" alt="disable-2fa" width="300"/>
<img src="screenshots/7 user-setting.png" alt="user-setting" width="300"/>

---

## 🚀 Getting Started

1. **Clone the Repository**
   ```bash
   git clone https://github.com/aivxx02/securecli.git
   cd securecli

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   
3. Configure `.env` File
   Create a .env file in the project root:
   ```bash
   SUPABASE_URL=https://your-supabase-url.supabase.co
   SUPABASE_KEY=your-supabase-anon-key
   EMAIL_ADDRESS=your@gmail.com
   EMAIL_PASSWORD=your_app_password
   
4. Run the App
   ```bash
   python securecli.py


