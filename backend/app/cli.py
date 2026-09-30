"""Command line administrative tasks."""

import argparse
import getpass
import sys
from app.core.security import hash_password, validate_password_policy, PasswordPolicyError
from app.db import SessionLocal
from app.models.user import User


def create_admin():
    parser = argparse.ArgumentParser(description="Create an Aegis platform administrator account.")
    parser.add_argument("--email", required=True, help="Administrator email address")
    args = parser.parse_args(sys.argv[2:])

    email = args.email.strip().lower()
    password = getpass.getpass("Enter administrator password: ")
    confirm_password = getpass.getpass("Confirm administrator password: ")

    if password != confirm_password:
        print("[!] Error: Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    try:
        validate_password_policy(password)
    except PasswordPolicyError as e:
        print(f"[!] Password policy violation: {e}", file=sys.stderr)
        sys.exit(1)

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"[!] Error: An account with email '{email}' already exists.", file=sys.stderr)
            sys.exit(1)

        admin_user = User(
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        print(f"[+] Administrator account '{email}' (ID: {admin_user.id}) created successfully.")
    finally:
        db.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin()
    else:
        print("Usage: python -m app.cli create-admin --email <email>")
        sys.exit(1)


if __name__ == "__main__":
    main()
