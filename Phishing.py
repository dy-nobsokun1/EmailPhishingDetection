from flask import Flask, render_template, request, redirect, url_for
import imaplib
import email
from email.header import decode_header
import chardet
import logging

app = Flask(__name__)


logging.basicConfig(level=logging.DEBUG)


def decode_subject(subject):
    decoded_bytes, encoding = decode_header(subject)[0]
    if isinstance(decoded_bytes, bytes):
        return decoded_bytes.decode(encoding or 'utf-8')
    return decoded_bytes

# Function to decode the email body with detected encoding
def decode_body(body):
    try:
        return body.decode('utf-8')
    except UnicodeDecodeError:
        encoding = chardet.detect(body)['encoding']
        return body.decode(encoding)

# Function to fetch emails
def fetch_emails(username, app_password, imap_server, mailbox='INBOX', num_emails=10):
    emails = []
    try:
        # Connect to the server using SSL
        mail = imaplib.IMAP4_SSL(imap_server)
        # Login to your account
        mail.login(username, app_password)
        # Select the mailbox you want to use
        mail.select(mailbox)

        # Search for all emails in the mailbox
        status, messages = mail.search(None, 'ALL')
        # Convert messages to a list of email IDs
        email_ids = messages[0].split()

        logging.debug(f"Found {len(email_ids)} emails")

        # Fetch the last `num_emails` email IDs (most recent)
        latest_email_ids = email_ids[-num_emails:]

        # Iterate through each email
        for email_id in reversed(latest_email_ids):  # Reverse to process from newest to oldest
            # Fetch the email by ID
            status, msg_data = mail.fetch(email_id, '(RFC822)')

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    # Decode the email subject
                    subject = decode_subject(msg['Subject'])
                    # Decode the email sender
                    from_ = decode_subject(msg.get('From'))
                    # Get the date
                    date = msg['Date']

                    # Initialize the email content
                    email_content = {
                        "id": email_id.decode(),
                        "subject": subject,
                        "from": from_,
                        "body": "",
                        "date": date
                    }

                    # If the email message is multipart
                    if msg.is_multipart():
                        # Iterate over email parts
                        for part in msg.walk():
                            # Extract content type of email
                            content_type = part.get_content_type()

                            try:
                                # Get the email body
                                body = part.get_payload(decode=True)
                                if body:
                                    email_content["body"] += decode_body(body)
                            except Exception as e:
                                logging.error(f"Error decoding part: {e}")
                    else:
                        # Extract content type of email
                        content_type = msg.get_content_type()

                        # Get the email body
                        body = msg.get_payload(decode=True)
                        if body:
                            email_content["body"] = decode_body(body)

                    # Append the snippet of the body
                    email_content["snippet"] = email_content["body"][:100] + '...' if len(email_content["body"]) > 100 else email_content["body"]

                    emails.append(email_content)

        # Close the connection and logout
        mail.close()
        mail.logout()
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

    return emails

# Function to fetch a single email by ID
def fetch_email_by_id(username, app_password, imap_server, email_id, mailbox='INBOX'):
    email_content = {}
    try:
        # Connect to the server using SSL
        mail = imaplib.IMAP4_SSL(imap_server)
        # Login to your account
        mail.login(username, app_password)
        # Select the mailbox you want to use
        mail.select(mailbox)
        status, msg_data = mail.fetch(email_id, '(RFC822)')

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                # Decode the email subject
                subject = decode_subject(msg['Subject'])
                # Decode the email sender
                from_ = decode_subject(msg.get('From'))
                # Get the date
                date = msg['Date']

                # Initialize the email content
                email_content = {
                    "subject": subject,
                    "from": from_,
                    "body": "",
                    "date": date
                }

                # If the email message is multipart
                if msg.is_multipart():
                    # Iterate over email parts
                    for part in msg.walk():
                        # Extract content type of email
                        content_type = part.get_content_type()

                        try:
                            # Get the email body
                            body = part.get_payload(decode=True)
                            if body:
                                email_content["body"] += decode_body(body)
                        except Exception as e:
                            logging.error(f"Error decoding part: {e}")
                else:
                    # Extract content type of email
                    content_type = msg.get_content_type()

                    # Get the email body
                    body = msg.get_payload(decode=True)
                    if body:
                        email_content["body"] = decode_body(body)

        # Close the connection and logout
        mail.close()
        mail.logout()
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

    return email_content

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/fetch-emails', methods=['POST'])
def fetch_emails_route():
    username = request.form.get('username')
    app_password = request.form.get('app_password')
    imap_server = request.form.get('imap_server')

    logging.debug(f"Fetching emails for user: {username} with server: {imap_server}")

    emails = fetch_emails(username, app_password, imap_server)
    logging.debug(f"Fetched {len(emails)} emails")
    return render_template('emails.html', emails=emails, username=username, app_password=app_password, imap_server=imap_server)

@app.route('/email/<email_id>')
def email_detail(email_id):
    username = request.args.get('username')
    app_password = request.args.get('app_password')
    imap_server = request.args.get('imap_server')

    if not username or not app_password or not imap_server:
        logging.error("Missing parameters for fetching email details.")
        return "Missing parameters", 400

    email_content = fetch_email_by_id(username, app_password, imap_server, email_id)
    return render_template('email_detail.html', email=email_content)

if __name__ == '__main__':
    app.run(host='localhost', port=5002, debug=True)
