#!/usr/bin/env python3
"""Send an HTML notification through the homelab SMTP account."""

import argparse
import email.message
import smtplib
import ssl
import sys
from pathlib import Path

SMTP_TIMEOUT_SECONDS = 30


def load_smtp_config():
    config = {}
    config_path = Path(__file__).parent / ".smtp_config"
    for line in config_path.read_text().strip().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()
    return config


def send(subject: str, body: str, recipients: list[str]):
    config = load_smtp_config()

    msg = email.message.EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config["SMTP_USERNAME"]
    msg["To"] = ", ".join(recipients)
    msg.set_content(body, subtype="html")

    with smtplib.SMTP(config["SMTP_ADDRESS"], int(config["SMTP_PORT"]), timeout=SMTP_TIMEOUT_SECONDS) as server:
        server.starttls(context=ssl.create_default_context())
        server.login(config["SMTP_USERNAME"], config["SMTP_PASSWORD"])
        server.send_message(msg)

    print(f"Sent to {', '.join(recipients)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True)
    parser.add_argument("--body-file", required=True, help="Path to file containing HTML body")
    parser.add_argument("--to", required=True, nargs="+", help="Recipient email addresses")
    args = parser.parse_args()

    body = Path(args.body_file).read_text()
    send(args.subject, body, args.to)
