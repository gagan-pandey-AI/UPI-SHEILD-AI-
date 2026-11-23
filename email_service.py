"""SMTP delivery helpers for password reset messages."""

from email.message import EmailMessage
import smtplib
import ssl


def send_password_reset_email(config, recipient, otp):
    """Send the reset code over authenticated TLS without logging message data."""
    use_ssl = bool(config.get("MAIL_USE_SSL"))
    use_tls = bool(config.get("MAIL_USE_TLS"))
    username = config.get("MAIL_USERNAME")
    password = config.get("MAIL_PASSWORD")
    if use_ssl == use_tls or bool(username) != bool(password):
        raise ValueError("SMTP settings are incomplete or conflicting.")

    message = EmailMessage()
    message["Subject"] = "UPI Shield AI password reset code"
    message["From"] = config["MAIL_FROM"]
    message["To"] = recipient
    message.set_content(
        f"Your UPI Shield AI password reset code is {otp}. "
        f"It expires in {config['PASSWORD_RESET_TTL_SECONDS'] // 60} minutes. "
        "If you did not request this, you can ignore this message."
    )

    timeout = config["MAIL_TIMEOUT_SECONDS"]
    context = ssl.create_default_context()
    if use_ssl:
        with smtplib.SMTP_SSL(
            config["MAIL_HOST"], config["MAIL_PORT"], timeout=timeout, context=context,
        ) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(
            config["MAIL_HOST"], config["MAIL_PORT"], timeout=timeout,
        ) as smtp:
            smtp.starttls(context=context)
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
