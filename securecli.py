import pyotp
import bcrypt
import qrcode
import io
import os
import sys
import time
import smtplib
import re
from getpass import getpass
from email.message import EmailMessage
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def mask_email(email):
    # Split email into username and domain
    username, domain = email.split("@")
    
    # If username is too short, just show first and last letter
    if len(username) <= 6:
        masked = username[0] + "*****" + username[-1]
    else:
        # Hide 5 characters starting from the 2nd character
        masked = username[:2] + "*****" + username[7:]
    
    return masked + "@" + domain


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def show_qr_code(secret, username):
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureCLI")
    qr = qrcode.make(uri)
    qr.show()
    print(f"\033[92mSecret:\033[0m {secret}")
    print("\033[92mScan this QR code with your chosen Authenticator app.\033[0m")


def hacker_loading(message="Processing", duration=1):
    sys.stdout.write(f"\033[92m{message}")
    sys.stdout.flush()
    for _ in range(duration * 4):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.25)
    sys.stdout.write("\033[0m\n")


def ask_authenticator_choice():
    while True:
        print("\n📲 Choose your Authenticator method:")
        print("╔════════════════════════════════╗")
        print("║ [1] 📱 Google Authenticator    ║")
        print("║ [2] 🔐 Microsoft Authenticator ║")
        print("║ [3] ✉️ Email (Recovery Mode)   ║")
        print("╚════════════════════════════════╝")
        choice = input("👉 Your choice (1/2/3): ").strip()

        if choice in {"1", "2", "3"}:
            hacker_loading("⚙️ Processing choice", 1)
            if choice == "1":
                return "Google"
            elif choice == "2":
                return "Microsoft"
            elif choice == "3":
                return "Email"
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")


def send_email_otp(recipient_email, otp):
    msg = EmailMessage()
    msg["Subject"] = "Your SecureCLI OTP Code"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = recipient_email
    msg.set_content(f"Your OTP code is: {otp}\n\nUse this to complete your 2FA setup.")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"📧 OTP sent to your \033[96m{mask_email(recipient_email)}\033[0m.")
        return True
    except Exception as e:
        print(f"\n❌ Failed to send email: {e}")
        return False


def register():
    username = input("\033[92mChoose a username: \033[0m")

    # Validate password
    for attempt in range(2):
        password = getpass("\033[92mChoose a password (min 4 characters): \033[0m")
        if len(password) >= 4:
            break
        print(f"❌ Password must be at least 4 characters long. Attempts left: {1 - attempt}")
    else:
        print("❌ Too many invalid attempts. Registration aborted.")
        return

    # Validate email
    for attempt in range(2):
        email = input("\033[92mEnter your email address: \033[0m").strip()
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
            break
        print(f"❌ Invalid email format. Attempts left: {1 - attempt}")
    else:
        print("❌ Too many invalid email attempts. Registration aborted.")
        return

    existing = supabase.table("users").select("*").eq("username", username).execute()
    if existing.data:
        print("❌ Username already exists.")
        return

    enable_2fa = input("Enable 2FA? (y/n): ").lower() == 'y'
    totp_secret = pyotp.random_base32() if enable_2fa else ""
    auth_app = None

    if enable_2fa:
        auth_app = ask_authenticator_choice()
        if auth_app == "Email":
            otp = pyotp.TOTP(totp_secret).now()
            if not send_email_otp(email, otp):
                print("❌ Email OTP delivery failed. Aborting 2FA.")
                totp_secret = ""
                enable_2fa = False
                auth_app = None
            else:
                entered = input("Enter OTP sent to email: ")
                if not pyotp.TOTP(totp_secret).verify(entered, valid_window=2):
                    print("❌ Invalid OTP. 2FA setup failed.")
                    totp_secret = ""
                    enable_2fa = False
                    auth_app = None
                else:
                    print("✅ Email 2FA setup complete.")
        else:
            show_qr_code(totp_secret, username)
            otp = input("Enter current OTP: ")
            if not pyotp.TOTP(totp_secret).verify(otp, valid_window=2):
                print("❌ Invalid OTP. 2FA setup failed.")
                totp_secret = ""
                enable_2fa = False
                auth_app = None
            else:
                print("✅ 2FA setup complete.")

    hashed_pw = hash_password(password)
    supabase.table("users").insert({
        "username": username,
        "password_hash": hashed_pw,
        "email": email,
        "is_2fa_enabled": enable_2fa,
        "totp_secret": totp_secret,
        "auth_app": auth_app
    }).execute()
    print("✅ Registration complete!")


def login():
    username = input("🙍🏼‍♂️ \033[92mUsername: \033[0m")
    password = getpass("🔒 \033[92mPassword: \033[0m")

    hacker_loading("\n🔍 Verifying credentials", 1)
    hacker_loading("🔍 Verifying identity", 1)

    response = supabase.table("users").select("*").eq("username", username).execute()
    if not response.data:
        print("❌ User not found. Please register.")
        return None

    user_data = response.data[0]

    if not verify_password(password, user_data["password_hash"]):
        print("❌ Incorrect password.")
        return None

    if user_data["is_2fa_enabled"]:
        print("🔐 \033[92m2FA is currently: ON\033[0m\n")
        print(f"\033[96mAuthenticator: {user_data.get('auth_app', 'Unknown')}\033[0m")
        auth_method = user_data.get("auth_app", "Unknown")

        if auth_method == "Email":
            hacker_loading("⚙️ OTP sending to your email", 1)
            otp = pyotp.TOTP(user_data["totp_secret"]).now()
            send_email_otp(user_data["email"], otp)
            entered = input("Enter OTP sent to your email: ")
        else:
            entered = input("Enter OTP: ")

        if not pyotp.TOTP(user_data["totp_secret"]).verify(entered, valid_window=2):
            print("❌ Invalid OTP.")
            return None

        hacker_loading("🔓 OTP verified", 1)
        print("✅ Access granted.")
    else:
        print("⚠️ \033[91m2FA is currently: OFF\033[0m")

    return user_data


def enable_2fa(user):
    print("\n\033[93m[⚙️] Setting up 2FA...\033[0m")
    auth_app = ask_authenticator_choice()
    secret = pyotp.random_base32()

    if auth_app == "Email":
        otp = pyotp.TOTP(secret).now()
        if not send_email_otp(user["email"], otp):
            print("❌ Email OTP delivery failed. Aborting 2FA.")
            return
        entered = input("Enter OTP sent to your email: ")
        if not pyotp.TOTP(secret).verify(entered, valid_window=2):
            print("❌ Invalid OTP. Aborting.")
            return
        print("✅ Email 2FA setup complete.")
    else:
        show_qr_code(secret, user["username"])
        otp = input("Enter current OTP: ")
        if not pyotp.TOTP(secret).verify(otp, valid_window=2):
            print("❌ Invalid OTP. Aborting.")
            return

    hacker_loading("⚙️ Enabling 2FA", 2)

    supabase.table("users").update({
        "is_2fa_enabled": True,
        "totp_secret": secret,
        "auth_app": auth_app
    }).eq("id", user["id"]).execute()
    print("✅ 2FA is now enabled!")


def disable_2fa(user):
    confirm = input("Are you sure you want to disable 2FA? (y/n): ").lower()
    if confirm != "y":
        print("❌ 2FA disable cancelled.")
        return
    
     # Ask for password confirmation
    password = getpass("🔐 Re-enter your password to confirm: ")
    if not verify_password(password, user["password_hash"]):
        print("❌ Incorrect password. Aborting 2FA disable.")
        return

    hacker_loading("⚠️ Disabling 2FA", 2)

    response = supabase.table("users").update({
        "is_2fa_enabled": False,
        "totp_secret": None,
        "auth_app": None
    }).eq("id", user["id"]).execute()
    if response.data:
        print("✅ 2FA has been disabled.")
    else:
        print("❌ Failed to disable 2FA. Debug info:", response)
    user["is_2fa_enabled"] = False
    user["totp_secret"] = None
    user["auth_app"] = None


def change_password(user):
    current = getpass("🔐 Enter current password: ")
    if not verify_password(current, user["password_hash"]):
        print("❌ Incorrect current password.")
        return

    for attempt in range(2):
        new_pw = getpass("🔐 Enter new password: ")
        if len(new_pw) < 4:
            print("❌ Password must be at least 4 characters.")
            continue
        confirm_pw = getpass("🔁 Confirm new password: ")
        if new_pw != confirm_pw:
            print("❌ Passwords do not match.")
            continue
        break
    else:
        print("❌ Too many failed attempts.")
        return

    hashed = hash_password(new_pw)
    supabase.table("users").update({
        "password_hash": hashed
    }).eq("id", user["id"]).execute()

    print("✅ Password changed successfully.")


def change_email(user):
    for attempt in range(2):
        new_email = input("📧 Enter new email address: ").strip()
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", new_email):
            break
        print("❌ Invalid email format.")
    else:
        print("❌ Too many invalid attempts.")
        return

    hacker_loading("✉️ Updating email", 2)
    supabase.table("users").update({
        "email": new_email
    }).eq("id", user["id"]).execute()

    print(f"✅ Email updated to: \033[96m{mask_email(new_email)}\033[0m")


def settings_menu(user):
    while True:
        print("\n" + "═" * 40)
        print("🛠️  \033[1;97mSECURECLI SETTINGS MENU\033[0m".center(40))
        print("═" * 40)
        print(" \033[92m1\033[0m. \033[97m🔑 Change Password\033[0m")
        print(" \033[92m2\033[0m. \033[97m📧 Change Email\033[0m")
        print(" \033[92m3\033[0m. \033[97m🔙 Back to Main Menu\033[0m")
        print("═" * 40)
        choice = input("👉 \033[1;97mSelect an option: \033[0m").strip()

        if choice == "1":
            change_password(user)
        elif choice == "2":
            change_email(user)
        elif choice == "3":
            print("\033[90m↩️ Returning to main menu...\033[0m")
            break
        else:
            print("\033[91m❌ Invalid choice.\033[0m")



def main():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print("\n" + "=" * 40)
        print("\033[1;92m🔐  WELCOME TO SECURECLI\033[0m".center(40))
        print("=" * 40)
        print("\033[92m[1]\033[0m Login")
        print("\033[92m[2]\033[0m Register")
        print("\033[92m[3]\033[0m Credits")
        print("\033[92m[4]\033[0m Exit")
        print("-" * 40)
        choice = input("👉 Choose an option: ").strip()

        if choice == "1":
            user = login()
            if user:
                while True:
                    print("\n" + "=" * 40)
                    print(f"🟢 \033[92mACCESS GRANTED\033[0m - Welcome back, agent!")
                    print("╔═════════════════════════════════════════╗")
                    print(f"║  Logged in as: \033[93m{user['username']:<24}\033[0m ║")
                    print("╚═════════════════════════════════════════╝")

                    print("2FA is currently:", "\033[92mON\033[0m" if user["is_2fa_enabled"] else "\033[91mOFF\033[0m")
                    if user["is_2fa_enabled"]:
                        print(f"🔐 Authenticator: \033[96m{user.get('auth_app', 'Unknown')}\033[0m")
                        print("Options: \033[93m[d]\033[0misable 2FA, \033[93m[s]\033[0mettings, \033[91m[l]\033[0mogout")
                    else:
                        print("Options: \033[93m[e]\033[0mnable 2FA, \033[93m[s]\033[0mettings, \033[91m[l]\033[0mogout")

                    action = input("Choose: ").lower()

                    if action == "e" and not user["is_2fa_enabled"]:
                        enable_2fa(user)
                        response = supabase.table("users").select("*").eq("id", user["id"]).single().execute()
                        user = response.data

                    elif action == "d" and user["is_2fa_enabled"]:
                        disable_2fa(user)
                        updated_user = supabase.table("users").select("*").eq("id", user["id"]).execute()
                        if updated_user.data:
                            user = updated_user.data[0]

                    elif action == "s":
                        settings_menu(user)
                        # Refresh user after changes
                        response = supabase.table("users").select("*").eq("id", user["id"]).single().execute()
                        user = response.data

                    elif action == "l":
                        hacker_loading("🔍 Logging out", 1)
                        print("👋 Logged out.")
                        break
                    else:
                        print("❌ Invalid choice.")


        elif choice == "2":
            register()
        elif choice == "3":
            print("\n👤 \033[93mAuthor: Anesh\033[0m")
            print("🔗 \033[93mGitHub: github.com/aivxx02\033[0m")
            print("📬 \033[93mEmail: aneshcode@gmail.com\033[0m")
            input("\nPress Enter to return...")
        elif choice == "4":
            hacker_loading("🔍 Exiting", 1)
            print("👋 Goodbye, agent.")
            break
        else:
            print("❌ Invalid option.")


if __name__ == "__main__":
    main()
