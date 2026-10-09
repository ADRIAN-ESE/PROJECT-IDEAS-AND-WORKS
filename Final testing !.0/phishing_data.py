"""
Phishing email examples for the Simulated Phishing feature.
Each example includes red-flag annotations for interactive detection.
"""

PHISHING_EXAMPLES = [
    {
        "id": "phish1",
        "difficulty": "beginner",
        "title": "Urgent Account Suspension",
        "from_name": "PayPal Security",
        "from_email": "security@paypa1-secure.com",
        "to": "you@example.com",
        "subject": "URGENT: Your PayPal account has been limited!",
        "date": "Today, 09:14 AM",
        "body_html": """
            <p>Dear Valued Customer,</p>
            <p>We have detected unusual activity on your PayPal account. To protect your funds, we have temporarily <strong>limited</strong> your account.</p>
            <p>You must verify your identity within <span style="color:red;font-weight:bold;">24 hours</span> or your account will be permanently suspended.</p>
            <p style="text-align:center;margin:24px 0;">
                <a href="http://paypa1-secure.com/verify" style="background:#0070ba;color:white;padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;">
                    Verify My Account Now
                </a>
            </p>
            <p>If you did not request this, please ignore this message and your account will be closed.</p>
            <p>Regards,<br>PayPal Security Team</p>
        """,
        "red_flags": [
            {
                "id": "rf1",
                "selector": "from_email",
                "label": "Suspicious sender domain",
                "description": "The domain is 'paypa1-secure.com' (with a '1' instead of 'l') — not the official paypal.com."
            },
            {
                "id": "rf2",
                "selector": "subject",
                "label": "Urgency and threats",
                "description": "Creates panic with 'URGENT' and threats of permanent suspension to force quick action."
            },
            {
                "id": "rf3",
                "selector": "body_link",
                "label": "Suspicious link destination",
                "description": "The button links to a non-PayPal domain. Hovering reveals the real URL."
            },
            {
                "id": "rf4",
                "selector": "greeting",
                "label": "Generic greeting",
                "description": "Uses 'Dear Valued Customer' instead of your actual name."
            }
        ],
        "is_phishing": True,
        "explanation": "This is a classic phishing email. Official PayPal never asks you to click links in emails to verify your account. Always go directly to paypal.com by typing the address yourself."
    },
    {
        "id": "phish2",
        "difficulty": "beginner",
        "title": "Package Delivery Notification",
        "from_name": "DHL Express",
        "from_email": "tracking@dhl-delivery-alerts.net",
        "to": "you@example.com",
        "subject": "Your package could not be delivered – Action required",
        "date": "Yesterday, 4:22 PM",
        "body_html": """
            <p>Hello,</p>
            <p>We attempted to deliver your package (Tracking #: DH928374651) but were unable to complete the delivery.</p>
            <p>Please confirm your shipping address and pay the small re-delivery fee of $1.99 to reschedule.</p>
            <p style="text-align:center;margin:24px 0;">
                <a href="http://dhl-delivery-alerts.net/reschedule" style="background:#ffcc00;color:#000;padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;">
                    Reschedule Delivery
                </a>
            </p>
            <p>Failure to respond within 48 hours will result in the package being returned to sender.</p>
            <p>DHL Customer Service</p>
        """,
        "red_flags": [
            {
                "id": "rf1",
                "selector": "from_email",
                "label": "Unofficial domain",
                "description": "Real DHL uses domains like dhl.com, not dhl-delivery-alerts.net."
            },
            {
                "id": "rf2",
                "selector": "body_link",
                "label": "Unexpected payment request",
                "description": "Legitimate carriers rarely ask for a small fee via email link for redelivery."
            },
            {
                "id": "rf3",
                "selector": "urgency",
                "label": "Time pressure",
                "description": "48-hour deadline creates urgency to act without verifying."
            }
        ],
        "is_phishing": True,
        "explanation": "Package scams are extremely common. Always check tracking on the official carrier website using a tracking number you already have."
    },
    {
        "id": "phish3",
        "difficulty": "intermediate",
        "title": "IT Support Password Reset",
        "from_name": "IT Helpdesk",
        "from_email": "it-support@company-mail.org",
        "to": "you@company.com",
        "subject": "Mandatory Password Reset – Compliance Requirement",
        "date": "Today, 11:03 AM",
        "body_html": """
            <p>Dear Employee,</p>
            <p>As part of our quarterly security compliance audit, all staff are required to reset their network passwords by end of day.</p>
            <p>Please use the secure portal below to complete your password reset:</p>
            <p style="text-align:center;margin:24px 0;">
                <a href="https://company-mail.org/reset" style="background:#2c3e50;color:white;padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;">
                    Reset Password Now
                </a>
            </p>
            <p>This is a mandatory action. Failure to comply may result in account lockout.</p>
            <p>IT Security Team<br>Internal Use Only</p>
        """,
        "red_flags": [
            {
                "id": "rf1",
                "selector": "from_email",
                "label": "Slightly off domain",
                "description": "The domain 'company-mail.org' may look similar to your real company domain but is not official."
            },
            {
                "id": "rf2",
                "selector": "body_link",
                "label": "External password reset link",
                "description": "Real IT departments usually direct you to internal portals or known SSO pages, not external links in email."
            },
            {
                "id": "rf3",
                "selector": "threat",
                "label": "Threat of lockout",
                "description": "Uses fear of account lockout to pressure immediate action."
            }
        ],
        "is_phishing": True,
        "explanation": "Spear-phishing often impersonates internal IT. Always verify password reset requests through official internal channels (helpdesk ticket system, known phone number, or in-person)."
    },
    {
        "id": "phish4",
        "difficulty": "intermediate",
        "title": "CEO Urgent Wire Transfer",
        "from_name": "Michael Thompson, CEO",
        "from_email": "m.thompson@company-ceo.com",
        "to": "finance@company.com",
        "subject": "Urgent Wire Transfer Needed – Confidential",
        "date": "Today, 8:47 AM",
        "body_html": """
            <p>Hi,</p>
            <p>I need you to process an urgent wire transfer of $48,500 to a new vendor. This is time-sensitive and confidential — please do not discuss with others.</p>
            <p>Bank details:</p>
            <ul>
                <li>Bank: First National Overseas</li>
                <li>Account: 8829347561</li>
                <li>SWIFT: FNOBUS33</li>
            </ul>
            <p>Please confirm once sent. I'm in meetings all day so email is best.</p>
            <p>Thanks,<br>Michael</p>
        """,
        "red_flags": [
            {
                "id": "rf1",
                "selector": "from_email",
                "label": "Spoofed or lookalike domain",
                "description": "CEO emails usually come from the official company domain, not a separate 'company-ceo.com'."
            },
            {
                "id": "rf2",
                "selector": "urgency_secrecy",
                "label": "Urgency + secrecy",
                "description": "Requests for secrecy and extreme urgency are classic Business Email Compromise (BEC) indicators."
            },
            {
                "id": "rf3",
                "selector": "wire_details",
                "label": "Unusual payment request",
                "description": "Unexpected large wire transfers should always be verified via a known phone number or in person."
            }
        ],
        "is_phishing": True,
        "explanation": "This is a Business Email Compromise (BEC) / CEO fraud attempt. Always verify high-value financial requests through a secondary channel you already trust."
    },
    {
        "id": "phish5",
        "difficulty": "advanced",
        "title": "Cloud Storage Shared Document",
        "from_name": "Microsoft OneDrive",
        "from_email": "no-reply@sharepoint-online.com",
        "to": "you@example.com",
        "subject": "Document shared with you: Q3_Financial_Review.docx",
        "date": "Today, 2:15 PM",
        "body_html": """
            <p><strong>John Smith</strong> shared a document with you.</p>
            <div style="border:1px solid #ddd;padding:16px;border-radius:6px;margin:16px 0;background:#f9f9f9;">
                <p style="margin:0;font-weight:bold;">📄 Q3_Financial_Review.docx</p>
                <p style="margin:4px 0;color:#666;font-size:0.9em;">Shared via OneDrive • 2.4 MB</p>
            </div>
            <p style="text-align:center;margin:24px 0;">
                <a href="https://sharepoint-online.com/view/doc?id=88293" style="background:#0078d4;color:white;padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;">
                    Open Document
                </a>
            </p>
            <p style="font-size:0.85em;color:#666;">If you don't recognize this, you can ignore this email.</p>
        """,
        "red_flags": [
            {
                "id": "rf1",
                "selector": "from_email",
                "label": "Lookalike domain",
                "description": "Microsoft uses microsoft.com / sharepoint.com domains. 'sharepoint-online.com' is not official."
            },
            {
                "id": "rf2",
                "selector": "unexpected_share",
                "label": "Unexpected document share",
                "description": "You weren't expecting a financial review document from 'John Smith'."
            },
            {
                "id": "rf3",
                "selector": "body_link",
                "label": "Credential harvesting link",
                "description": "The link leads to a fake Microsoft login page designed to steal credentials."
            }
        ],
        "is_phishing": True,
        "explanation": "Advanced phishing often mimics collaboration tools. Always open shared documents from within the official app or by navigating directly to the real service."
    },
    {
        "id": "safe1",
        "difficulty": "beginner",
        "title": "Legitimate Password Reset (Safe Example)",
        "from_name": "GitHub",
        "from_email": "noreply@github.com",
        "to": "you@example.com",
        "subject": "[GitHub] Please verify your email address",
        "date": "Today, 10:01 AM",
        "body_html": """
            <p>Hi there,</p>
            <p>Someone (hopefully you) requested a password reset for your GitHub account.</p>
            <p>If this was you, click the button below to reset your password. The link expires in 24 hours.</p>
            <p style="text-align:center;margin:24px 0;">
                <a href="https://github.com/password_reset/abc123" style="background:#2da44e;color:white;padding:12px 28px;text-decoration:none;border-radius:6px;font-weight:bold;">
                    Reset password
                </a>
            </p>
            <p>If you did not request this, you can safely ignore this email. Your password will not change.</p>
            <p>Thanks,<br>The GitHub Team</p>
        """,
        "red_flags": [],
        "is_phishing": False,
        "explanation": "This is a legitimate-looking example. Notice the correct domain (github.com), no threats, clear expiry, and the option to ignore if it wasn't you. Still, best practice is to navigate to GitHub yourself rather than clicking email links when possible."
    }
]


def get_phishing_examples(difficulty=None):
    if difficulty:
        return [e for e in PHISHING_EXAMPLES if e["difficulty"] == difficulty]
    return PHISHING_EXAMPLES


def get_phishing_by_id(example_id):
    for e in PHISHING_EXAMPLES:
        if e["id"] == example_id:
            return e
    return None
