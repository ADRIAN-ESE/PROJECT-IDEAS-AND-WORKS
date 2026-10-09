"""
Quiz question bank for Minimal Cyber Awareness App.
Organized by topic and difficulty.
"""

from itertools import combinations


QUIZ_TOPICS = [
    {
        "id": "phishing",
        "name": "Phishing",
        "description": "Recognize and avoid phishing attempts",
        "icon": "🎣",
        "color": "hsl(0, 85%, 60%)"
    },
    {
        "id": "passwords",
        "name": "Passwords",
        "description": "Create and manage strong passwords",
        "icon": "🔐",
        "color": "hsl(170, 80%, 50%)"
    },
    {
        "id": "social-engineering",
        "name": "Social Engineering",
        "description": "Defend against manipulation tactics",
        "icon": "🎭",
        "color": "hsl(280, 90%, 65%)"
    },
    {
        "id": "data-protection",
        "name": "Data Protection",
        "description": "Keep your personal data safe",
        "icon": "🛡️",
        "color": "hsl(45, 100%, 60%)"
    },
    {
        "id": "safe-browsing",
        "name": "Safe Browsing",
        "description": "Browse the web securely",
        "icon": "🌐",
        "color": "hsl(200, 90%, 55%)"
    },
    {
        "id": "wifi-security",
        "name": "Wi-Fi Security",
        "description": "Secure your wireless connections",
        "icon": "📶",
        "color": "hsl(320, 80%, 60%)"
    },
    {
        "id": "device-security",
        "name": "Device Security",
        "description": "Protect computers and mobile devices",
        "icon": "💻",
        "color": "hsl(190, 80%, 55%)"
    },
    {
        "id": "incident-response",
        "name": "Incident Response",
        "description": "Respond calmly when something goes wrong",
        "icon": "🚨",
        "color": "hsl(25, 90%, 60%)"
    },
    {
        "id": "cyber-law",
        "name": "Cyber Law",
        "description": "Understand legal duties and responsible security conduct",
        "icon": "⚖️",
        "color": "hsl(210, 75%, 55%)"
    },
    {
        "id": "governance",
        "name": "Cyber Governance",
        "description": "Manage cybersecurity risk, accountability, and oversight",
        "icon": "🏛️",
        "color": "hsl(145, 65%, 45%)"
    },
    {
        "id": "cyber-threat-management",
        "name": "Cyber Threat Management",
        "description": "Assess threats, prioritize risk, and coordinate defensive action",
        "icon": "🎯",
        "color": "hsl(15, 85%, 58%)"
    }
]

QUESTIONS = {
    "phishing": [
        {
            "id": "ph1",
            "difficulty": "beginner",
            "question": "What is phishing?",
            "options": [
                "A type of fishing sport",
                "A fraudulent attempt to obtain sensitive information by disguising as a trustworthy entity",
                "A method to speed up internet connection",
                "A software update process"
            ],
            "correct": 1,
            "explanation": "Phishing is a cyber attack where attackers impersonate legitimate organizations to steal personal data like passwords, credit card numbers, or bank details."
        },
        {
            "id": "ph2",
            "difficulty": "beginner",
            "question": "Which of the following is a common red flag in a phishing email?",
            "options": [
                "A personalized greeting with your full name",
                "Urgent language demanding immediate action",
                "A link to the official company website",
                "Proper grammar and spelling"
            ],
            "correct": 1,
            "explanation": "Phishing emails often create a sense of urgency ('Act now or your account will be closed!') to pressure victims into acting without thinking."
        },
        {
            "id": "ph3",
            "difficulty": "intermediate",
            "question": "You receive an email from 'support@paypa1.com' asking you to verify your account. What should you do?",
            "options": [
                "Click the link and enter your credentials immediately",
                "Reply with your account details",
                "Hover over the link to inspect the URL, then go directly to the official site",
                "Forward the email to all your contacts"
            ],
            "correct": 2,
            "explanation": "Always inspect the actual URL (paypa1.com uses a '1' instead of 'l'). Never click suspicious links—navigate to the official site yourself."
        },
        {
            "id": "ph4",
            "difficulty": "intermediate",
            "question": "What is spear phishing?",
            "options": [
                "Phishing attacks targeting large groups randomly",
                "Highly targeted phishing attacks aimed at specific individuals or organizations",
                "A type of malware that infects USB drives",
                "An attack that only works on mobile devices"
            ],
            "correct": 1,
            "explanation": "Spear phishing is personalized. Attackers research their targets and craft convincing messages using personal details."
        },
        {
            "id": "ph5",
            "difficulty": "advanced",
            "question": "Which technique do attackers use to make phishing emails look legitimate?",
            "options": [
                "Using official logos and branding",
                "Spoofing the 'From' address",
                "Creating lookalike domains",
                "All of the above"
            ],
            "correct": 3,
            "explanation": "Attackers combine multiple techniques: stolen logos, spoofed sender addresses, and domains that look almost identical to the real ones (e.g., rnicrosoft.com)."
        },
        {
            "id": "ph6",
            "difficulty": "beginner",
            "question": "What should you do if you accidentally click a phishing link?",
            "options": [
                "Ignore it and hope nothing happens",
                "Immediately change passwords and run antivirus scans",
                "Share the link with friends to warn them",
                "Reply to the email asking if it's real"
            ],
            "correct": 1,
            "explanation": "Disconnect from the internet if possible, change passwords from a different device, enable MFA, and scan for malware."
        },
        {
            "id": "ph7",
            "difficulty": "intermediate",
            "question": "What is a 'homograph attack' in phishing?",
            "options": [
                "Using similar-looking characters from different alphabets in domain names",
                "Sending the same phishing email repeatedly",
                "Attacking only government websites",
                "Using voice calls instead of emails"
            ],
            "correct": 0,
            "explanation": "Homograph attacks use characters that look identical (e.g., Cyrillic 'а' vs Latin 'a') to create fake domains that appear genuine."
        },
        {
            "id": "ph8",
            "difficulty": "advanced",
            "question": "Which of these is the MOST secure way to verify a suspicious email claiming to be from your bank?",
            "options": [
                "Call the phone number provided in the email",
                "Reply to the email asking for confirmation",
                "Log into your account via the official app or website using a bookmark",
                "Click the 'unsubscribe' link"
            ],
            "correct": 2,
            "explanation": "Never use contact details from a suspicious email. Always use known official channels (app, bookmarked site, or verified phone number)."
        },
        {
            "id": "ph9",
            "difficulty": "beginner",
            "question": "True or False: Legitimate companies will never ask for your password via email.",
            "options": [
                "True",
                "False"
            ],
            "correct": 0,
            "explanation": "Legitimate organizations never ask for passwords, PINs, or full credit card numbers via email. This is a classic phishing indicator."
        },
        {
            "id": "ph10",
            "difficulty": "intermediate",
            "question": "What is 'vishing'?",
            "options": [
                "Phishing via SMS text messages",
                "Phishing via voice calls",
                "Phishing via social media DMs",
                "Phishing via QR codes"
            ],
            "correct": 1,
            "explanation": "Vishing (voice phishing) involves phone calls where attackers impersonate trusted entities to extract information."
        },
        {
            "id": "ph11",
            "difficulty": "beginner",
            "question": "Which action is safest when an email asks you to open an unexpected attachment?",
            "options": [
                "Open it if the sender name looks familiar",
                "Verify the request through a separate trusted channel",
                "Forward it to a colleague to test",
                "Disable antivirus before opening it"
            ],
            "correct": 1,
            "explanation": "Unexpected attachments can deliver malware. Verify the request independently before opening anything."
        },
        {
            "id": "ph12",
            "difficulty": "intermediate",
            "question": "Why can a shortened URL be risky in a message?",
            "options": [
                "It always downloads a virus",
                "It hides the destination and makes inspection harder",
                "It cannot use HTTPS",
                "It only works on mobile devices"
            ],
            "correct": 1,
            "explanation": "URL shorteners conceal the final destination. Use a trusted scanner or navigate to the service directly."
        },
        {
            "id": "ph13",
            "difficulty": "intermediate",
            "question": "What is smishing?",
            "options": [
                "Phishing through SMS or messaging apps",
                "Phishing through a printer",
                "A password hashing method",
                "A secure email standard"
            ],
            "correct": 0,
            "explanation": "Smishing is SMS-based phishing. Treat unexpected delivery, banking, and account messages with caution."
        },
        {
            "id": "ph14",
            "difficulty": "advanced",
            "question": "What is the best response to a suspected phishing message at work?",
            "options": [
                "Delete it without reporting it",
                "Report it using the organization’s approved process",
                "Reply and ask the sender to prove their identity",
                "Post a screenshot publicly"
            ],
            "correct": 1,
            "explanation": "Reporting helps security teams block similar messages and protect other users."
        },
        {
            "id": "ph15",
            "difficulty": "advanced",
            "question": "Why should you distrust an email that passes a basic spelling check?",
            "options": [
                "Good spelling proves it is malicious",
                "Modern phishing can be well-written and carefully personalized",
                "Legitimate companies never use punctuation",
                "Spelling is the only reliable indicator"
            ],
            "correct": 1,
            "explanation": "Grammar is only one signal. Check the request, sender domain, link destination, and context together."
        },
        {
            "id": "ph16",
            "difficulty": "intermediate",
            "question": "A message from 'Payroll' says your direct-deposit details will be frozen unless you sign in through its link today. What is the safest next step?",
            "options": [
                "Use the link because payroll messages are time-sensitive",
                "Open the payroll site from a saved bookmark or contact HR using a known channel",
                "Reply with your employee number to confirm your identity",
                "Forward the message to coworkers and ask them to test the link"
            ],
            "correct": 1,
            "explanation": "Urgency and account-change requests are common lures. Verify through a known route rather than using contact details or links in the message.",
        },
        {
            "id": "ph17",
            "difficulty": "advanced",
            "question": "A QR code on a parking notice leads to a payment page with a slightly misspelled domain. What should you do?",
            "options": [
                "Pay a small amount to see whether the page works",
                "Scan it again on another phone",
                "Do not enter payment details; use the parking operator's official app or site",
                "Trust it if the page displays the operator's logo"
            ],
            "correct": 2,
            "explanation": "QR codes can hide phishing destinations. Verify the domain independently and use a known official payment channel.",
        }
    ],
    "passwords": [
        {
            "id": "pw1",
            "difficulty": "beginner",
            "question": "What makes a password strong?",
            "options": [
                "Using your birthday and name",
                "Long length, mix of character types, and uniqueness",
                "Using the same password everywhere for consistency",
                "Writing it on a sticky note for easy access"
            ],
            "correct": 1,
            "explanation": "Strong passwords are long (12+ characters), use uppercase, lowercase, numbers, and symbols, and are unique to each account."
        },
        {
            "id": "pw2",
            "difficulty": "beginner",
            "question": "Why is password reuse dangerous?",
            "options": [
                "It makes passwords easier to remember",
                "If one account is breached, attackers can access all accounts using the same password",
                "It slows down login times",
                "Websites ban reused passwords"
            ],
            "correct": 1,
            "explanation": "Credential stuffing attacks use leaked username/password pairs from one breach to try logging into other services."
        },
        {
            "id": "pw3",
            "difficulty": "intermediate",
            "question": "What is the best practice for managing many unique passwords?",
            "options": [
                "Write them all in a notebook",
                "Use a reputable password manager",
                "Use slight variations of one master password",
                "Store them in a browser without a master password"
            ],
            "correct": 1,
            "explanation": "Password managers generate, store, and autofill strong unique passwords. Protect them with a strong master password and MFA."
        },
        {
            "id": "pw4",
            "difficulty": "intermediate",
            "question": "What does MFA (Multi-Factor Authentication) add?",
            "options": [
                "A second password",
                "An additional verification factor beyond just the password",
                "Faster login times",
                "Automatic password changes"
            ],
            "correct": 1,
            "explanation": "MFA requires something you know (password) + something you have (phone/app) or something you are (biometrics)."
        },
        {
            "id": "pw5",
            "difficulty": "advanced",
            "question": "Which authentication method is generally more secure than SMS-based 2FA?",
            "options": [
                "Email codes",
                "Authenticator apps (TOTP) or hardware security keys",
                "Security questions",
                "None — SMS is the strongest"
            ],
            "correct": 1,
            "explanation": "SMS can be intercepted via SIM swapping. Authenticator apps and hardware keys (like YubiKey) are significantly more resistant."
        },
        {
            "id": "pw6",
            "difficulty": "beginner",
            "question": "How often should you change your passwords?",
            "options": [
                "Every week, regardless of any issues",
                "Only when there is a known breach or suspicion of compromise",
                "Never — strong passwords don't need changing",
                "Every time you log in"
            ],
            "correct": 1,
            "explanation": "Forced frequent changes often lead to weaker passwords. Change them when compromised, or use a password manager for unique strong ones."
        },
        {
            "id": "pw7",
            "difficulty": "intermediate",
            "question": "What is 'password spraying'?",
            "options": [
                "Trying many passwords against one account",
                "Trying a few common passwords against many accounts",
                "Spraying water on a keyboard",
                "Using a password manager to generate passwords"
            ],
            "correct": 1,
            "explanation": "Password spraying tests common passwords (like 'Password123') across many accounts to avoid lockouts from too many attempts on one account."
        },
        {
            "id": "pw8",
            "difficulty": "advanced",
            "question": "What is the primary advantage of a passphrase over a complex short password?",
            "options": [
                "They are shorter",
                "They are easier to remember while providing high entropy",
                "They never need to be changed",
                "They work better with older systems"
            ],
            "correct": 1,
            "explanation": "A long passphrase like 'correct-horse-battery-staple' is memorable and has more entropy than a short complex password like 'P@ssw0rd!'."
        },
        {
            "id": "pw9",
            "difficulty": "beginner",
            "question": "Should you share your password with a trusted colleague?",
            "options": [
                "Yes, if they need temporary access",
                "No — use proper access sharing features instead",
                "Yes, but only verbally",
                "Only if they promise not to write it down"
            ],
            "correct": 1,
            "explanation": "Never share passwords. Use temporary access, guest accounts, or password manager sharing features designed for this purpose."
        },
        {
            "id": "pw10",
            "difficulty": "intermediate",
            "question": "What should a password manager's master password be like?",
            "options": [
                "Short and simple since it's the only one you remember",
                "Extremely strong, unique, and ideally a long passphrase",
                "The same as your email password",
                "Written down next to your computer"
            ],
            "correct": 1,
            "explanation": "Your master password unlocks everything. Make it very strong and consider enabling biometric unlock or hardware key for convenience."
        },
        {
            "id": "pw11",
            "difficulty": "beginner",
            "question": "What is the safest place to generate a new password?",
            "options": [
                "A reputable password manager",
                "A public social media poll",
                "Your name with a number added",
                "A password shared by your team"
            ],
            "correct": 0,
            "explanation": "Password managers can generate long, random, and unique passwords without relying on predictable personal details."
        },
        {
            "id": "pw12",
            "difficulty": "intermediate",
            "question": "What is credential stuffing?",
            "options": [
                "Trying leaked username and password pairs on other services",
                "Encrypting a password before storage",
                "Adding symbols to a passphrase",
                "Locking an account after one failed login"
            ],
            "correct": 0,
            "explanation": "Credential stuffing relies on password reuse. Unique passwords prevent one breach from unlocking other accounts."
        },
        {
            "id": "pw13",
            "difficulty": "intermediate",
            "question": "Which MFA method is generally most resistant to phishing?",
            "options": [
                "A code sent by email",
                "A code read over a phone call",
                "A hardware security key using a passkey standard",
                "The same password twice"
            ],
            "correct": 2,
            "explanation": "Hardware-backed passkeys and security keys verify the genuine site origin, making captured codes much less useful."
        },
        {
            "id": "pw14",
            "difficulty": "advanced",
            "question": "Why should password reset questions avoid publicly known facts?",
            "options": [
                "They make accounts load slowly",
                "Answers may be found through social media or public records",
                "They prevent MFA from working",
                "They are always encrypted with the password"
            ],
            "correct": 1,
            "explanation": "Answers based on birthdays, pets, or schools can often be researched or guessed. Use randomly generated answers where allowed."
        },
        {
            "id": "pw15",
            "difficulty": "advanced",
            "question": "What should you do after learning that a service suffered a breach?",
            "options": [
                "Reuse the exposed password with a symbol",
                "Change that unique password and any reused passwords immediately",
                "Wait until someone contacts you directly",
                "Disable all account alerts"
            ],
            "correct": 1,
            "explanation": "Change the exposed credential and any reused versions, enable MFA, and monitor the account for suspicious activity."
        },
        {
            "id": "pw16",
            "difficulty": "intermediate",
            "question": "Your password manager reports that one saved site's password appeared in a breach. You reused it on two other sites. What should you do first?",
            "options": [
                "Change it only on the breached site and keep the other copies",
                "Change it on all three sites to unique passwords and enable MFA where available",
                "Add an exclamation mark to the shared password",
                "Delete the breach alert"
            ],
            "correct": 1,
            "explanation": "Attackers try exposed credentials on other services. Replace every reused instance with a unique password and add MFA.",
        },
        {
            "id": "pw17",
            "difficulty": "advanced",
            "question": "You receive repeated MFA approval prompts while you are not signing in. What is the safest response?",
            "options": [
                "Approve one to stop the notifications",
                "Deny the prompts, report them, and secure the account through its official site",
                "Share a one-time code with the person who called claiming to be IT",
                "Turn off MFA and continue using the account"
            ],
            "correct": 1,
            "explanation": "Unexpected prompts can indicate someone has your password. Deny them, report the activity, and change the password from a trusted device.",
        }
    ],
    "social-engineering": [
        {
            "id": "se1",
            "difficulty": "beginner",
            "question": "What is social engineering?",
            "options": [
                "Building social networks online",
                "Psychological manipulation to trick people into revealing information or performing actions",
                "A type of software engineering",
                "Creating fake social media profiles for marketing"
            ],
            "correct": 1,
            "explanation": "Social engineering exploits human psychology rather than technical vulnerabilities."
        },
        {
            "id": "se2",
            "difficulty": "beginner",
            "question": "Which is an example of social engineering?",
            "options": [
                "A stranger calling claiming to be IT support and asking for your password",
                "Installing antivirus software",
                "Updating your operating system",
                "Using a VPN"
            ],
            "correct": 0,
            "explanation": "Impersonating IT support is a classic pretexting / social engineering tactic."
        },
        {
            "id": "se3",
            "difficulty": "intermediate",
            "question": "What is 'pretexting'?",
            "options": [
                "Creating a fabricated scenario to engage a victim",
                "Sending mass phishing emails",
                "Guessing passwords",
                "Physical theft of devices"
            ],
            "correct": 0,
            "explanation": "Pretexting involves inventing a story (pretext) to gain trust and extract information."
        },
        {
            "id": "se4",
            "difficulty": "intermediate",
            "question": "What is 'baiting'?",
            "options": [
                "Leaving infected USB drives in public places hoping someone plugs them in",
                "Fishing with a rod",
                "Calling people repeatedly",
                "Sending fake invoices"
            ],
            "correct": 0,
            "explanation": "Baiting uses physical media (or digital downloads) that look appealing but contain malware."
        },
        {
            "id": "se5",
            "difficulty": "advanced",
            "question": "How can you best protect against social engineering?",
            "options": [
                "Never answer the phone",
                "Verify identities through independent channels and be skeptical of unsolicited requests",
                "Share personal information freely to build trust",
                "Disable all security software"
            ],
            "correct": 1,
            "explanation": "Always verify unexpected requests by contacting the person/organization through a known official channel."
        },
        {
            "id": "se6",
            "difficulty": "beginner",
            "question": "An email from your 'CEO' urgently asks for a wire transfer. What should you do?",
            "options": [
                "Process it immediately to avoid delays",
                "Verify the request through a known phone number or in-person",
                "Reply asking for bank details",
                "Ignore company policy for speed"
            ],
            "correct": 1,
            "explanation": "Business Email Compromise (BEC) often impersonates executives. Always verify high-value requests out-of-band."
        },
        {
            "id": "se7",
            "difficulty": "intermediate",
            "question": "What is 'quid pro quo' in social engineering?",
            "options": [
                "Offering a service or benefit in exchange for information or access",
                "Threatening the victim",
                "Using technical exploits only",
                "Stealing physical documents"
            ],
            "correct": 0,
            "explanation": "Attackers may pose as tech support offering 'help' in exchange for login credentials."
        },
        {
            "id": "se8",
            "difficulty": "advanced",
            "question": "Why are social engineering attacks often more effective than pure technical attacks?",
            "options": [
                "They require less technical skill",
                "Humans are often the weakest link in security",
                "They are easier to detect",
                "They only work on unsecured systems"
            ],
            "correct": 1,
            "explanation": "Even with strong technical controls, people can be manipulated into bypassing them."
        },
        {
            "id": "se9",
            "difficulty": "beginner",
            "question": "Someone at the office door says they forgot their badge. What is the safest response?",
            "options": [
                "Hold the door open for them",
                "Ask them to use the visitor process or contact security",
                "Give them your badge temporarily",
                "Ignore them"
            ],
            "correct": 1,
            "explanation": "Tailgating is a common physical social engineering tactic. Always follow access control procedures."
        },
        {
            "id": "se10",
            "difficulty": "intermediate",
            "question": "What should you do if you suspect you are being targeted by social engineering?",
            "options": [
                "Continue the conversation to gather more information alone",
                "Report it to your security team or IT department immediately",
                "Post about it on social media",
                "Nothing — most are harmless"
            ],
            "correct": 1,
            "explanation": "Early reporting helps protect the organization and may prevent the attack from succeeding."
        },
        {
            "id": "se11",
            "difficulty": "beginner",
            "question": "Which three emotions are commonly exploited by social engineers?",
            "options": [
                "Urgency, fear, and curiosity",
                "Calmness, patience, and doubt",
                "Sleep, hunger, and boredom",
                "None; social engineering uses only software bugs"
            ],
            "correct": 0,
            "explanation": "Attackers often trigger urgency, fear, curiosity, or helpfulness to bypass careful decision-making."
        },
        {
            "id": "se12",
            "difficulty": "intermediate",
            "question": "What is the safest way to confirm an unexpected request from a coworker?",
            "options": [
                "Use the contact details in the request",
                "Reply with sensitive information first",
                "Contact them through a known, separate channel",
                "Ask an unknown person nearby"
            ],
            "correct": 2,
            "explanation": "Independent verification prevents an attacker from controlling both the request and the confirmation path."
        },
        {
            "id": "se13",
            "difficulty": "intermediate",
            "question": "What is tailgating?",
            "options": [
                "Following an authorized person through a secure entrance",
                "Sending repeated marketing emails",
                "Guessing a Wi-Fi password",
                "Watching a user type from a distance"
            ],
            "correct": 0,
            "explanation": "Tailgating is a physical access tactic. Politely direct visitors to reception instead of holding secure doors open."
        },
        {
            "id": "se14",
            "difficulty": "advanced",
            "question": "What is business email compromise (BEC)?",
            "options": [
                "A company-wide antivirus update",
                "Impersonating an executive or supplier to request money or data",
                "A physical theft from an office",
                "A secure email backup"
            ],
            "correct": 1,
            "explanation": "BEC uses trusted business identities and timing to persuade staff to transfer funds or disclose information."
        },
        {
            "id": "se15",
            "difficulty": "advanced",
            "question": "Why should you avoid volunteering extra personal details during an unsolicited call?",
            "options": [
                "Attackers can use them to build a more convincing pretext",
                "It automatically deletes your account",
                "Personal details cannot be misused",
                "It makes the call encrypted"
            ],
            "correct": 0,
            "explanation": "Small details can be combined into a convincing identity profile for later manipulation or impersonation."
        },
        {
            "id": "se16",
            "difficulty": "intermediate",
            "question": "A caller claiming to be from IT says they need the six-digit code just sent to your phone to stop an attack. What should you do?",
            "options": [
                "Read the code because the caller knows your name",
                "Decline, end the call, and contact IT through the published help-desk channel",
                "Send the code by text instead of reading it aloud",
                "Ask the caller to prove it by stating your password"
            ],
            "correct": 1,
            "explanation": "A one-time code can authorize account access. Do not share it; independently contact the real support team.",
        },
        {
            "id": "se17",
            "difficulty": "advanced",
            "question": "A regular supplier emails new bank details just before an invoice is due. What is the best control before paying?",
            "options": [
                "Reply to the email to confirm the account number",
                "Verify the change using a known supplier contact and follow payment approval rules",
                "Pay a small test amount to the new account",
                "Accept the change if the email signature looks familiar"
            ],
            "correct": 1,
            "explanation": "Business email compromise often targets payment changes. Independently verify through a previously trusted number or contact and use dual approval where required.",
        }
    ],
    "data-protection": [
        {
            "id": "dp1",
            "difficulty": "beginner",
            "question": "What is the primary purpose of data encryption?",
            "options": [
                "To make files smaller",
                "To make data unreadable without the correct key",
                "To speed up data transfer",
                "To delete data permanently"
            ],
            "correct": 1,
            "explanation": "Encryption transforms data into ciphertext that can only be decrypted with the proper key."
        },
        {
            "id": "dp2",
            "difficulty": "beginner",
            "question": "Why should you avoid public Wi-Fi for sensitive transactions?",
            "options": [
                "It is always slower",
                "Traffic can be intercepted by attackers on the same network",
                "It costs money",
                "It doesn't support HTTPS"
            ],
            "correct": 1,
            "explanation": "Public networks are often unencrypted or poorly secured, allowing man-in-the-middle attacks."
        },
        {
            "id": "dp3",
            "difficulty": "intermediate",
            "question": "What does GDPR primarily regulate?",
            "options": [
                "Software licensing",
                "Protection of personal data of individuals in the EU",
                "Internet speed standards",
                "Cryptocurrency trading"
            ],
            "correct": 1,
            "explanation": "The General Data Protection Regulation sets strict rules on how personal data of EU residents must be handled."
        },
        {
            "id": "dp4",
            "difficulty": "intermediate",
            "question": "What is the 3-2-1 backup rule?",
            "options": [
                "3 copies, 2 different media types, 1 offsite",
                "Backup every 3 days, 2 times a day, 1 verification",
                "3 passwords, 2 FA, 1 recovery email",
                "3 devices, 2 accounts, 1 password"
            ],
            "correct": 0,
            "explanation": "Keep at least three copies of data, on two different types of storage, with one copy stored offsite."
        },
        {
            "id": "dp5",
            "difficulty": "advanced",
            "question": "What is 'data minimization'?",
            "options": [
                "Collecting and retaining only the data necessary for a specific purpose",
                "Compressing data to save space",
                "Deleting all data after 30 days",
                "Sharing data with as few people as possible"
            ],
            "correct": 0,
            "explanation": "Data minimization reduces risk by limiting the amount of personal data collected and stored."
        },
        {
            "id": "dp6",
            "difficulty": "beginner",
            "question": "Before disposing of an old hard drive, you should:",
            "options": [
                "Throw it in the trash",
                "Securely wipe or physically destroy it",
                "Give it to a friend",
                "Format it once using the OS"
            ],
            "correct": 1,
            "explanation": "Simple formatting doesn't securely erase data. Use secure wipe tools or physical destruction."
        },
        {
            "id": "dp7",
            "difficulty": "intermediate",
            "question": "What is the difference between a full backup and an incremental backup?",
            "options": [
                "Full copies everything; incremental only copies changes since the last backup",
                "They are the same thing",
                "Incremental is always larger",
                "Full backups are never needed"
            ],
            "correct": 0,
            "explanation": "Incremental backups save time and space by only capturing changes, but restoring requires the full backup plus all incrementals."
        },
        {
            "id": "dp8",
            "difficulty": "advanced",
            "question": "What is end-to-end encryption (E2EE)?",
            "options": [
                "Data is encrypted only while in transit",
                "Only the communicating users can read the messages; the service provider cannot",
                "Encryption applied only on the server",
                "A type of firewall"
            ],
            "correct": 1,
            "explanation": "With E2EE, even the service provider cannot access the plaintext content."
        },
        {
            "id": "dp9",
            "difficulty": "beginner",
            "question": "Why is it important to review app permissions on your phone?",
            "options": [
                "To make apps run faster",
                "To limit unnecessary access to your personal data and sensors",
                "Permissions don't matter",
                "To increase battery life only"
            ],
            "correct": 1,
            "explanation": "Many apps request more permissions than needed. Review and revoke unnecessary ones regularly."
        },
        {
            "id": "dp10",
            "difficulty": "intermediate",
            "question": "What should you do if you receive a data breach notification from a service you use?",
            "options": [
                "Ignore it if you haven't noticed any issues",
                "Change your password, enable MFA, and monitor accounts for suspicious activity",
                "Delete the email",
                "Post your details online for help"
            ],
            "correct": 1,
            "explanation": "Act quickly: change credentials, enable extra security, and watch for identity theft or fraud."
        },
        {
            "id": "dp11",
            "difficulty": "beginner",
            "question": "What is personal data?",
            "options": [
                "Only a person’s password",
                "Information that can identify or relate to an individual",
                "Any file larger than one megabyte",
                "Only data stored online"
            ],
            "correct": 1,
            "explanation": "Personal data includes identifiers such as names, contact details, IDs, location data, and online identifiers."
        },
        {
            "id": "dp12",
            "difficulty": "intermediate",
            "question": "What does least privilege mean?",
            "options": [
                "Giving every user administrator access",
                "Giving users only the access needed for their role",
                "Deleting unused accounts once a year",
                "Using the shortest possible password"
            ],
            "correct": 1,
            "explanation": "Least privilege limits the impact of mistakes or compromised accounts by reducing unnecessary access."
        },
        {
            "id": "dp13",
            "difficulty": "intermediate",
            "question": "Why should sensitive files be encrypted before being stored in cloud storage?",
            "options": [
                "Encryption makes files impossible to delete",
                "It adds protection if the storage account or sharing settings are compromised",
                "It guarantees the provider cannot lose data",
                "It removes the need for backups"
            ],
            "correct": 1,
            "explanation": "Encryption adds a layer of protection beyond the provider’s access controls and account security."
        },
        {
            "id": "dp14",
            "difficulty": "advanced",
            "question": "What is a data retention policy used for?",
            "options": [
                "To keep every file forever",
                "To define how long data is needed and when it should be securely deleted",
                "To make passwords shorter",
                "To publish confidential records"
            ],
            "correct": 1,
            "explanation": "Retention policies reduce exposure by removing data that no longer has a legitimate business or legal purpose."
        },
        {
            "id": "dp15",
            "difficulty": "advanced",
            "question": "What should you do if you accidentally send confidential data to the wrong recipient?",
            "options": [
                "Delete your sent-mail folder",
                "Report the incident promptly using the approved process",
                "Wait to see whether they mention it",
                "Forward even more context"
            ],
            "correct": 1,
            "explanation": "Fast reporting gives the organization a chance to recall access, contact the recipient, and reduce harm."
        },
        {
            "id": "dp16",
            "difficulty": "intermediate",
            "question": "A spreadsheet containing customer details was shared with 'anyone with the link' instead of your project team. What should you do?",
            "options": [
                "Remove public access, report the exposure promptly, and preserve relevant details for responders",
                "Delete the spreadsheet and say nothing",
                "Ask the unintended audience to forward it to you",
                "Assume the provider will notify your organization automatically"
            ],
            "correct": 0,
            "explanation": "Restrict access if authorized, then report immediately so responders can assess access logs, scope, and any notification duties.",
        },
        {
            "id": "dp17",
            "difficulty": "advanced",
            "question": "A team finds an old export of customer records that is no longer needed for its work. What is the best next step?",
            "options": [
                "Keep another copy in personal cloud storage as a precaution",
                "Follow the approved retention and legal-hold process, then securely dispose of unneeded copies",
                "Email the file to the whole team before deleting it",
                "Rename it so it is harder to find"
            ],
            "correct": 1,
            "explanation": "Keep personal data only for a documented business or legal need. Confirm retention and legal holds before secure disposal.",
        }
    ],
    "safe-browsing": [
        {
            "id": "sb1",
            "difficulty": "beginner",
            "question": "What does HTTPS indicate?",
            "options": [
                "The site is government-approved",
                "The connection between your browser and the site is encrypted",
                "The site has no ads",
                "The site is free"
            ],
            "correct": 1,
            "explanation": "HTTPS uses TLS to encrypt data in transit, protecting against eavesdropping and tampering."
        },
        {
            "id": "sb2",
            "difficulty": "beginner",
            "question": "You see a padlock icon in the address bar. What does it mean?",
            "options": [
                "The site is completely safe and free of malware",
                "The connection is encrypted (HTTPS)",
                "The site is owned by a large company",
                "Your antivirus is active"
            ],
            "correct": 1,
            "explanation": "The padlock only confirms encryption of the connection — not that the site itself is trustworthy or free of malicious content."
        },
        {
            "id": "sb3",
            "difficulty": "intermediate",
            "question": "What is a good practice when downloading software?",
            "options": [
                "Download from any site that ranks high on Google",
                "Prefer official websites or trusted app stores and verify checksums when possible",
                "Always use the first download button you see",
                "Disable antivirus temporarily for faster downloads"
            ],
            "correct": 1,
            "explanation": "Official sources reduce the risk of trojanized software. Checksums help verify file integrity."
        },
        {
            "id": "sb4",
            "difficulty": "intermediate",
            "question": "What is a 'drive-by download'?",
            "options": [
                "Downloading files while driving",
                "Malware that installs automatically when visiting a compromised website",
                "A type of legal software update",
                "Downloading via Bluetooth"
            ],
            "correct": 1,
            "explanation": "Drive-by downloads exploit browser or plugin vulnerabilities without requiring a click."
        },
        {
            "id": "sb5",
            "difficulty": "advanced",
            "question": "What is the purpose of a Content Security Policy (CSP)?",
            "options": [
                "To block all JavaScript",
                "To mitigate XSS and data injection attacks by controlling resource loading",
                "To encrypt all page content",
                "To speed up page loading"
            ],
            "correct": 1,
            "explanation": "CSP headers tell the browser which sources of content are allowed, reducing the impact of XSS."
        },
        {
            "id": "sb6",
            "difficulty": "beginner",
            "question": "Why should you be cautious of browser extensions?",
            "options": [
                "They always slow down the browser",
                "Malicious or poorly coded extensions can steal data or inject ads",
                "They are illegal",
                "They only work offline"
            ],
            "correct": 1,
            "explanation": "Extensions often have broad permissions. Install only from trusted sources and review permissions."
        },
        {
            "id": "sb7",
            "difficulty": "intermediate",
            "question": "What is 'clickjacking'?",
            "options": [
                "A technique that tricks users into clicking something different from what they perceive",
                "Clicking too fast on links",
                "A type of password attack",
                "An advertising method"
            ],
            "correct": 0,
            "explanation": "Clickjacking overlays invisible elements so users perform unintended actions."
        },
        {
            "id": "sb8",
            "difficulty": "advanced",
            "question": "What does 'certificate pinning' help protect against?",
            "options": [
                "Weak passwords",
                "Man-in-the-middle attacks using fraudulent certificates",
                "Phishing emails",
                "Physical theft"
            ],
            "correct": 1,
            "explanation": "Certificate pinning ensures the app/browser only accepts a specific expected certificate, making rogue CAs less effective."
        },
        {
            "id": "sb9",
            "difficulty": "beginner",
            "question": "You receive a browser warning that a site's certificate is invalid. What should you do?",
            "options": [
                "Click 'Proceed anyway' to save time",
                "Do not proceed — the connection may not be secure",
                "Disable certificate checking permanently",
                "Only proceed if the site looks familiar"
            ],
            "correct": 1,
            "explanation": "Invalid certificates can indicate interception or misconfiguration. Avoid the site until verified."
        },
        {
            "id": "sb10",
            "difficulty": "intermediate",
            "question": "What is a good habit when using public computers?",
            "options": [
                "Stay logged into all accounts for convenience",
                "Use private/incognito mode, avoid sensitive logins, and clear data after",
                "Install your password manager",
                "Save passwords in the browser"
            ],
            "correct": 1,
            "explanation": "Public computers may have keyloggers or residual data. Prefer your own device and clear sessions."
        },
        {
            "id": "sb11",
            "difficulty": "beginner",
            "question": "Why are software updates important for security?",
            "options": [
                "They only change the app icon",
                "They often fix known vulnerabilities attackers could exploit",
                "They remove the need for antivirus",
                "They make every website trustworthy"
            ],
            "correct": 1,
            "explanation": "Updates frequently include patches for vulnerabilities that are already known to attackers."
        },
        {
            "id": "sb12",
            "difficulty": "intermediate",
            "question": "What should you check before installing a browser extension?",
            "options": [
                "Its permissions, publisher, reviews, and need for access",
                "Whether it has the brightest icon",
                "Whether it requests every available permission",
                "Whether it was shared in an unknown pop-up"
            ],
            "correct": 0,
            "explanation": "Review the publisher and permissions carefully. Remove extensions that are unused or overly intrusive."
        },
        {
            "id": "sb13",
            "difficulty": "intermediate",
            "question": "What is a secure way to handle a pop-up claiming your device is infected?",
            "options": [
                "Call the number in the pop-up",
                "Install the recommended cleaner immediately",
                "Close the tab and run a scan with trusted security software",
                "Give the support agent remote access"
            ],
            "correct": 2,
            "explanation": "Fake security alerts are common scams. Use trusted software and official support channels instead."
        },
        {
            "id": "sb14",
            "difficulty": "advanced",
            "question": "What is DNS filtering useful for?",
            "options": [
                "Blocking requests to known malicious or unwanted domains",
                "Making passwords unnecessary",
                "Guaranteeing every website is safe",
                "Encrypting files on your device"
            ],
            "correct": 0,
            "explanation": "DNS filtering can block known malicious destinations, but it is one layer and cannot replace user judgment."
        },
        {
            "id": "sb15",
            "difficulty": "advanced",
            "question": "Why should you avoid entering sensitive information on a shared computer?",
            "options": [
                "Shared computers may contain malware, keyloggers, or saved sessions",
                "Shared computers cannot connect to HTTPS",
                "They always erase files immediately",
                "Private browsing makes them fully safe"
            ],
            "correct": 0,
            "explanation": "You cannot verify the security of a shared device. Prefer a trusted device for sensitive accounts and transactions."
        },
        {
            "id": "sb16",
            "difficulty": "intermediate",
            "question": "Your browser displays a certificate warning on your organization's payroll site. What should you do?",
            "options": [
                "Ignore the warning because the URL looks familiar",
                "Try a different browser until one lets you through",
                "Stop and contact IT through a known channel; do not enter credentials",
                "Disable browser security for the session"
            ],
            "correct": 2,
            "explanation": "A certificate warning can indicate a configuration problem or interception. Do not bypass it for a sensitive service; report it.",
        },
        {
            "id": "sb17",
            "difficulty": "beginner",
            "question": "A pop-up says your video meeting app is out of date and offers an installer from an unfamiliar site. What should you do?",
            "options": [
                "Install it if the pop-up uses the app's logo",
                "Close the pop-up and update through the app or vendor's official channel",
                "Disable antivirus to avoid installation errors",
                "Ask the pop-up for a support phone number"
            ],
            "correct": 1,
            "explanation": "Fake update prompts can deliver malware. Use the app's built-in updater or a verified vendor source.",
        }
    ],
    "wifi-security": [
        {
            "id": "wf1",
            "difficulty": "beginner",
            "question": "What is the strongest common Wi-Fi encryption standard currently recommended?",
            "options": [
                "WEP",
                "WPA",
                "WPA2",
                "WPA3"
            ],
            "correct": 3,
            "explanation": "WPA3 is the latest and most secure. Avoid WEP entirely; upgrade from WPA/WPA2 when possible."
        },
        {
            "id": "wf2",
            "difficulty": "beginner",
            "question": "Why should you change the default admin password on your router?",
            "options": [
                "Default passwords are widely known and can be used by attackers",
                "It makes the Wi-Fi faster",
                "It is required by law",
                "It improves signal strength"
            ],
            "correct": 0,
            "explanation": "Many routers ship with well-known default credentials that attackers scan for."
        },
        {
            "id": "wf3",
            "difficulty": "intermediate",
            "question": "What is a guest network useful for?",
            "options": [
                "Giving visitors internet access without exposing your main network devices",
                "Increasing overall Wi-Fi speed",
                "Hiding your network from neighbors",
                "Automatically updating devices"
            ],
            "correct": 0,
            "explanation": "Guest networks isolate visitors from your primary devices and shared resources."
        },
        {
            "id": "wf4",
            "difficulty": "intermediate",
            "question": "What does disabling WPS (Wi-Fi Protected Setup) help prevent?",
            "options": [
                "Slow connections",
                "Brute-force attacks that can crack the Wi-Fi password",
                "Device incompatibility",
                "Higher electricity usage"
            ],
            "correct": 1,
            "explanation": "WPS PIN can be brute-forced relatively easily on many routers. Disabling it improves security."
        },
        {
            "id": "wf5",
            "difficulty": "advanced",
            "question": "What is an 'evil twin' attack?",
            "options": [
                "A duplicate legitimate access point created by an attacker to intercept traffic",
                "Two routers with the same name fighting for signal",
                "A type of malware",
                "A hardware failure"
            ],
            "correct": 0,
            "explanation": "Attackers set up rogue APs with the same SSID to trick devices into connecting and capturing data."
        },
        {
            "id": "wf6",
            "difficulty": "beginner",
            "question": "When using public Wi-Fi, what additional protection is recommended?",
            "options": [
                "Turning off the firewall",
                "Using a reputable VPN",
                "Sharing the connection with others",
                "Disabling HTTPS"
            ],
            "correct": 1,
            "explanation": "A VPN encrypts your traffic so that others on the same network (or the network operator) cannot easily inspect it."
        },
        {
            "id": "wf7",
            "difficulty": "intermediate",
            "question": "Why is it risky to leave your home Wi-Fi network open (no password)?",
            "options": [
                "Neighbors can use your bandwidth and potentially perform illegal activities",
                "It makes your internet slower for everyone",
                "It violates most ISP terms",
                "All of the above"
            ],
            "correct": 3,
            "explanation": "Open networks invite unauthorized use, legal liability, and potential attacks on your devices."
        },
        {
            "id": "wf8",
            "difficulty": "advanced",
            "question": "What is MAC address filtering and how effective is it?",
            "options": [
                "A strong security control that cannot be bypassed",
                "A weak control — MAC addresses can be easily spoofed",
                "A method to encrypt traffic",
                "A way to increase range"
            ],
            "correct": 1,
            "explanation": "MAC filtering offers only minor security. Determined attackers can observe and spoof allowed addresses."
        },
        {
            "id": "wf9",
            "difficulty": "beginner",
            "question": "How often should you update your router's firmware?",
            "options": [
                "Never — firmware updates break things",
                "Whenever security updates are available",
                "Only when the router stops working",
                "Once every five years"
            ],
            "correct": 1,
            "explanation": "Router firmware updates often contain critical security patches. Enable automatic updates if available."
        },
        {
            "id": "wf10",
            "difficulty": "intermediate",
            "question": "What is the benefit of using a unique SSID (network name) instead of the default?",
            "options": [
                "It makes the network invisible",
                "It avoids revealing the router brand/model which can aid attackers",
                "It increases speed",
                "It is required for WPA3"
            ],
            "correct": 1,
            "explanation": "Default SSIDs often indicate the router model, helping attackers look up known vulnerabilities."
        },
        {
            "id": "wf11",
            "difficulty": "beginner",
            "question": "What should you do before connecting a smart device to your home Wi-Fi?",
            "options": [
                "Change default credentials and install available updates",
                "Disable all security settings",
                "Use the router’s factory password forever",
                "Connect it to every network nearby"
            ],
            "correct": 0,
            "explanation": "Changing defaults and patching devices reduces the chance that known credentials or vulnerabilities are abused."
        },
        {
            "id": "wf12",
            "difficulty": "intermediate",
            "question": "What is the safest response to an unknown open Wi-Fi network?",
            "options": [
                "Connect automatically for convenience",
                "Avoid it or use a trusted hotspot and VPN for necessary access",
                "Share your device files first",
                "Turn off your device firewall"
            ],
            "correct": 1,
            "explanation": "Unknown open networks may be monitored or impersonated. Prefer trusted networks and avoid sensitive activity."
        },
        {
            "id": "wf13",
            "difficulty": "intermediate",
            "question": "Why should router administration be disabled over the public internet?",
            "options": [
                "Remote exposure gives attackers another way to target the router",
                "It reduces the Wi-Fi password length",
                "It prevents local devices from connecting",
                "It disables WPA3"
            ],
            "correct": 0,
            "explanation": "Router administration should be limited to trusted local access or a secure management method."
        },
        {
            "id": "wf14",
            "difficulty": "advanced",
            "question": "What does network segmentation achieve?",
            "options": [
                "It separates devices or services so a compromise is easier to contain",
                "It makes all passwords identical",
                "It guarantees no device can be hacked",
                "It removes the need for firmware updates"
            ],
            "correct": 0,
            "explanation": "Separating guest, IoT, and primary devices can limit lateral movement after a device is compromised."
        },
        {
            "id": "wf15",
            "difficulty": "advanced",
            "question": "Why is WPA3-Personal with a strong passphrase preferable to WEP?",
            "options": [
                "WPA3 provides stronger modern protections; WEP is easily cracked",
                "WEP is newer and more secure",
                "WPA3 does not use encryption",
                "They provide exactly the same protection"
            ],
            "correct": 0,
            "explanation": "WEP is obsolete and can be broken quickly. Use WPA3 where supported, with a long unique passphrase."
        },
        {
            "id": "wf16",
            "difficulty": "intermediate",
            "question": "At a cafe, two Wi-Fi networks have nearly identical names. What is the safest action before connecting?",
            "options": [
                "Choose the one with the strongest signal",
                "Ask staff for the exact network name and avoid sensitive work on an untrusted network",
                "Connect to both and compare speed",
                "Use the network that has no password"
            ],
            "correct": 1,
            "explanation": "An attacker can create a lookalike access point. Confirm the exact network with staff; prefer a trusted connection for sensitive work.",
        },
        {
            "id": "wf17",
            "difficulty": "advanced",
            "question": "You need to access a work system while traveling and only have public Wi-Fi. Your organization provides a managed VPN. What is the best practice?",
            "options": [
                "Connect to any similarly named hotspot and turn off endpoint protection",
                "Use the verified network, managed VPN, and required MFA, while still treating links and sites cautiously",
                "Assume a VPN makes every website trustworthy",
                "Share the VPN credentials with a travel companion"
            ],
            "correct": 1,
            "explanation": "Follow organizational remote-access policy. A VPN protects a network path but does not make a malicious site or device safe.",
        }
    ],
    "device-security": [
        {
            "id": "ds1",
            "difficulty": "beginner",
            "question": "Why should you lock your screen when stepping away?",
            "options": ["To save battery only", "To prevent unauthorized access to your session", "To improve Wi-Fi speed", "To delete temporary files"],
            "correct": 1,
            "explanation": "A locked screen prevents someone nearby from accessing open accounts, files, or messages."
        },
        {
            "id": "ds2",
            "difficulty": "beginner",
            "question": "What is the safest source for mobile apps?",
            "options": ["Random links in messages", "Official app stores and trusted publishers", "Pop-up advertisements", "Unknown file-sharing sites"],
            "correct": 1,
            "explanation": "Official stores and verified publishers reduce the chance of installing modified or malicious applications."
        },
        {
            "id": "ds3",
            "difficulty": "beginner",
            "question": "Why are automatic updates useful?",
            "options": ["They remove the need for passwords", "They install security fixes promptly", "They guarantee every app is safe", "They stop all phishing"],
            "correct": 1,
            "explanation": "Automatic updates reduce the time a device remains exposed to known vulnerabilities."
        },
        {
            "id": "ds4",
            "difficulty": "beginner",
            "question": "What should you do with an unknown USB drive?",
            "options": ["Plug it in to identify the owner", "Use it on a personal computer first", "Give it to IT or security without opening it", "Copy its files to the cloud"],
            "correct": 2,
            "explanation": "Unknown removable media may contain malware. Report it through an approved process instead of opening it."
        },
        {
            "id": "ds5",
            "difficulty": "intermediate",
            "question": "What does endpoint protection help detect?",
            "options": ["Only slow internet", "Malware and suspicious activity on devices", "Incorrect weather forecasts", "Weak Wi-Fi signals"],
            "correct": 1,
            "explanation": "Endpoint protection monitors computers and mobile devices for malicious files and behavior."
        },
        {
            "id": "ds6",
            "difficulty": "intermediate",
            "question": "Why should you remove unused applications?",
            "options": ["Unused apps can have unpatched vulnerabilities and unnecessary permissions", "They make passwords stronger", "They prevent backups", "It disables device encryption"],
            "correct": 0,
            "explanation": "Reducing the software footprint limits unnecessary permissions and vulnerable components."
        },
        {
            "id": "ds7",
            "difficulty": "intermediate",
            "question": "What is device encryption designed to protect?",
            "options": ["Files if a device is lost or stolen", "A device from every online attack", "The quality of a camera", "Wi-Fi signal strength"],
            "correct": 0,
            "explanation": "Full-disk encryption helps prevent offline access to data when a device is physically lost or stolen."
        },
        {
            "id": "ds8",
            "difficulty": "intermediate",
            "question": "What is the principle of least privilege on a device?",
            "options": ["Use administrator access for every task", "Use only the permissions needed for the task", "Share one account with everyone", "Disable all access controls"],
            "correct": 1,
            "explanation": "Limited permissions reduce the damage a compromised application or account can cause."
        },
        {
            "id": "ds9",
            "difficulty": "advanced",
            "question": "Why should personal and work accounts remain separate?",
            "options": ["Separation limits data mixing and reduces cross-account exposure", "It makes MFA impossible", "It disables security updates", "It guarantees no account can be breached"],
            "correct": 0,
            "explanation": "Separate accounts and profiles reduce accidental sharing and help organizations apply appropriate controls."
        },
        {
            "id": "ds10",
            "difficulty": "advanced",
            "question": "What is secure boot intended to verify?",
            "options": ["The weather outside", "That trusted software starts before the operating system", "That a password is reused", "That Wi-Fi is public"],
            "correct": 1,
            "explanation": "Secure boot helps prevent unauthorized or tampered software from loading during startup."
        },
        {
            "id": "ds11",
            "difficulty": "beginner",
            "question": "What should you do if your phone is lost?",
            "options": ["Wait several days", "Use a device-finding service, lock it, and report it", "Post all account details online", "Disable your account alerts"],
            "correct": 1,
            "explanation": "Remote lock and location tools can protect data while reporting helps trigger organizational response."
        },
        {
            "id": "ds12",
            "difficulty": "intermediate",
            "question": "Why should you review mobile app permissions?",
            "options": ["To give every app more access", "To remove access an app does not need", "To disable screen locking", "To improve password reuse"],
            "correct": 1,
            "explanation": "Permission reviews reduce unnecessary access to location, contacts, camera, microphone, and files."
        },
        {
            "id": "ds13",
            "difficulty": "intermediate",
            "question": "What does a firewall primarily control?",
            "options": ["Network traffic entering or leaving a device or network", "The brightness of a screen", "The strength of a password", "The size of a hard drive"],
            "correct": 0,
            "explanation": "Firewalls apply rules to network connections and can block unwanted traffic."
        },
        {
            "id": "ds14",
            "difficulty": "advanced",
            "question": "Why should backups be protected from the device being backed up?",
            "options": ["Ransomware could encrypt or delete connected backups", "It makes files smaller", "It disables recovery", "Backups never contain sensitive data"],
            "correct": 0,
            "explanation": "Offline or access-controlled backups are more resilient if the primary device is compromised."
        },
        {
            "id": "ds15",
            "difficulty": "advanced",
            "question": "What is application allowlisting?",
            "options": ["Allowing every downloaded program", "Permitting only approved applications to run", "Sharing apps publicly", "Removing all device logs"],
            "correct": 1,
            "explanation": "Allowlisting limits execution to known approved software and reduces unauthorized code execution."
        },
        {
            "id": "ds16",
            "difficulty": "beginner",
            "question": "You find an unmarked USB drive in the office parking lot. What should you do?",
            "options": [
                "Plug it into your work computer to identify its owner",
                "Give it to IT or security without connecting it to a device",
                "Take it home and inspect it there",
                "Insert it into a shared printer"
            ],
            "correct": 1,
            "explanation": "Unknown removable media can contain malicious files. Turn it over to the approved team for safe handling.",
        },
        {
            "id": "ds17",
            "difficulty": "intermediate",
            "question": "A mobile app for viewing a PDF asks for administrator access and permission to read all contacts. What is the safest response?",
            "options": [
                "Grant everything so the PDF opens faster",
                "Deny unnecessary access and use an approved app or contact IT",
                "Share your device PIN with the app publisher",
                "Disable the device's security updates"
            ],
            "correct": 1,
            "explanation": "An app should receive only permissions needed for its purpose. Unexpected broad access is a reason to stop and verify.",
        }
    ],
    "incident-response": [
        {
            "id": "ir1",
            "difficulty": "beginner",
            "question": "What is the first priority when you suspect an incident?",
            "options": ["Hide the evidence", "Stay calm and report it through the approved channel", "Post about it publicly", "Delete all files"],
            "correct": 1,
            "explanation": "Prompt reporting lets trained responders contain the issue while preserving useful evidence."
        },
        {
            "id": "ir2",
            "difficulty": "beginner",
            "question": "What should you do after entering a password into a suspicious site?",
            "options": ["Reuse it everywhere", "Change it from a trusted device and report the event", "Ignore it", "Send it to support by email"],
            "correct": 1,
            "explanation": "Change the exposed password, protect other accounts where it was reused, and report the incident quickly."
        },
        {
            "id": "ir3",
            "difficulty": "beginner",
            "question": "Why should you avoid deleting suspicious emails immediately?",
            "options": ["They may contain evidence useful to responders", "Deletion makes malware stronger", "Email cannot be reported", "It automatically shares the message"],
            "correct": 0,
            "explanation": "Preserve the message according to policy so security teams can investigate headers, links, and attachments."
        },
        {
            "id": "ir4",
            "difficulty": "beginner",
            "question": "What is containment in incident response?",
            "options": ["Limiting the spread or impact of an incident", "Publishing the incident online", "Deleting every backup", "Ignoring affected systems"],
            "correct": 0,
            "explanation": "Containment isolates affected accounts, devices, or networks while the incident is investigated."
        },
        {
            "id": "ir5",
            "difficulty": "intermediate",
            "question": "Why is preserving timestamps and logs important?",
            "options": ["They help reconstruct what happened and when", "They make passwords longer", "They prevent all breaches", "They replace reporting"],
            "correct": 0,
            "explanation": "Accurate timelines help responders identify the entry point, scope, and actions needed for recovery."
        },
        {
            "id": "ir6",
            "difficulty": "intermediate",
            "question": "What is eradication?",
            "options": ["Removing the root cause and malicious artifacts", "Turning off all alerts", "Ignoring the affected account", "Creating a phishing email"],
            "correct": 0,
            "explanation": "Eradication removes malware, unauthorized access, and the weaknesses that allowed the incident."
        },
        {
            "id": "ir7",
            "difficulty": "intermediate",
            "question": "What is recovery in an incident response plan?",
            "options": ["Returning systems to normal operation while monitoring them", "Deleting all evidence", "Blaming a user", "Disabling backups"],
            "correct": 0,
            "explanation": "Recovery restores trusted services and watches for signs that the incident is returning."
        },
        {
            "id": "ir8",
            "difficulty": "intermediate",
            "question": "Why should an incident be documented after it is resolved?",
            "options": ["Lessons learned can improve controls and response plans", "Documentation makes attacks legal", "It removes the need for training", "It guarantees the same issue cannot happen"],
            "correct": 0,
            "explanation": "Post-incident reviews identify improvements to technology, policies, training, and communication."
        },
        {
            "id": "ir9",
            "difficulty": "advanced",
            "question": "What is an indicator of compromise (IOC)?",
            "options": ["A clue suggesting a device or account may be compromised", "A password policy", "A backup schedule", "A normal software update"],
            "correct": 0,
            "explanation": "IOCs include suspicious hashes, domains, processes, login patterns, or other evidence of compromise."
        },
        {
            "id": "ir10",
            "difficulty": "advanced",
            "question": "Why should responders avoid changing a compromised system without guidance?",
            "options": ["Changes can destroy evidence or affect investigation", "The system becomes faster", "It makes backups unnecessary", "Attackers receive an automatic alert"],
            "correct": 0,
            "explanation": "Uncoordinated changes can overwrite logs or alter evidence. Follow the incident team’s instructions."
        },
        {
            "id": "ir11",
            "difficulty": "beginner",
            "question": "Who should receive a suspected security incident report?",
            "options": ["The approved IT, security, or help-desk channel", "A public forum", "Only your friends", "No one unless money was lost"],
            "correct": 0,
            "explanation": "Use the organization’s official reporting route so the right responders can triage the event."
        },
        {
            "id": "ir12",
            "difficulty": "intermediate",
            "question": "What is an incident severity level used for?",
            "options": ["To prioritize response based on impact and urgency", "To rank employee popularity", "To hide incidents", "To replace technical investigation"],
            "correct": 0,
            "explanation": "Severity helps teams allocate resources and escalate incidents proportionately."
        },
        {
            "id": "ir13",
            "difficulty": "intermediate",
            "question": "What should you do if ransomware starts encrypting files?",
            "options": ["Disconnect the device from networks and report immediately", "Keep opening files", "Pay without reporting", "Connect every backup drive"],
            "correct": 0,
            "explanation": "Isolation may limit spread. Follow the response plan and never connect unprotected backups to an affected system."
        },
        {
            "id": "ir14",
            "difficulty": "advanced",
            "question": "What is a chain of custody for digital evidence?",
            "options": ["A record of who handled evidence and how it was preserved", "A password sharing method", "A network cable standard", "A list of installed apps"],
            "correct": 0,
            "explanation": "Chain-of-custody records support evidence integrity and accountability during investigations."
        },
        {
            "id": "ir15",
            "difficulty": "advanced",
            "question": "What is the purpose of an incident response tabletop exercise?",
            "options": ["To rehearse roles and decisions before a real incident", "To test monitor brightness", "To publish confidential data", "To replace all security tools"],
            "correct": 0,
            "explanation": "Tabletop exercises reveal gaps in communication, responsibilities, and procedures without real-world damage."
        },
        {
            "id": "ir16",
            "difficulty": "intermediate",
            "question": "A cloud provider tells your team it detected suspicious access to a shared customer-data workspace. What should your organization do first?",
            "options": [
                "Wait for the provider to decide whether the event matters",
                "Activate your incident process, coordinate with the provider, and preserve relevant evidence",
                "Delete the workspace before checking logs",
                "Post the provider's message publicly"
            ],
            "correct": 1,
            "explanation": "Use the response plan, establish scope with the provider, preserve evidence, and involve security, privacy, and legal roles as appropriate.",
        },
        {
            "id": "ir17",
            "difficulty": "beginner",
            "question": "You accidentally email a customer file to the wrong external address. What should you do?",
            "options": [
                "Report it promptly through the approved incident channel and provide the relevant details",
                "Delete the sent message and assume the issue is resolved",
                "Ask the recipient to forward the file to your personal email",
                "Wait to see whether anyone notices"
            ],
            "correct": 0,
            "explanation": "Prompt reporting lets responders assess exposure, attempt authorized containment, and determine any required next steps.",
            }

    ],
    "cyber-law": [
        {
            "id": "cl1",
            "difficulty": "beginner",
            "question": "You notice a coworker's account can open a customer record unrelated to their work. What is the safest and most responsible action?",
            "options": [
                "Open more records to see how widespread the access is",
                "Do not inspect further; report the access-control issue through the approved channel",
                "Copy the records as evidence to a personal device",
                "Post the record online so the organization responds"
            ],
            "correct": 1,
            "explanation": "Access only data you are authorized to use. Stop exploring and report the concern; legal rules depend on jurisdiction and circumstances.",
        },
        {
            "id": "cl2",
            "difficulty": "intermediate",
            "question": "A company acting as a GDPR data controller becomes aware of a personal-data breach that is likely to risk individuals' rights and freedoms. What is the general regulator-notification rule?",
            "options": [
                "Notify the competent supervisory authority without undue delay and, where feasible, within 72 hours of awareness",
                "Wait 72 days before deciding whether to notify",
                "Notify only if the affected people request it",
                "No notification is ever required if the data was encrypted"
            ],
            "correct": 0,
            "explanation": "Under GDPR Article 33, a controller generally notifies the supervisory authority without undue delay and, where feasible, within 72 hours unless the breach is unlikely to risk individuals' rights and freedoms. Consult privacy counsel; other laws may differ.",
            "source": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
            "source_label": "GDPR, Article 33"
        },
        {
            "id": "cl3",
            "difficulty": "intermediate",
            "question": "A security researcher reports that your public site exposes records they could view without logging in. What should your team do?",
            "options": [
                "Ask them to download a larger sample before responding",
                "Use the published vulnerability-disclosure process, limit further access, and preserve the report",
                "Threaten legal action before verifying the report",
                "Tell them to post the records publicly"
            ],
            "correct": 1,
            "explanation": "A clear disclosure process helps route reports safely. Do not encourage unnecessary access or collection; involve security and legal teams.",
        },
        {
            "id": "cl4",
            "difficulty": "beginner",
            "question": "A colleague says, 'The breach happened, so deleting the affected logs is harmless.' What is the best response?",
            "options": [
                "Delete them to reduce the organization's liability",
                "Preserve relevant records and follow incident, legal-hold, and evidence-handling instructions",
                "Edit timestamps to make the timeline easier to read",
                "Send copies to a personal account"
            ],
            "correct": 1,
            "explanation": "Preserve evidence and follow counsel's instructions. Retention, disclosure, and reporting duties depend on the facts and applicable law.",
        },
        {
            "id": "cl5",
            "difficulty": "intermediate",
            "question": "A product team wants to collect government ID numbers 'in case they are useful later,' but has no defined purpose. What should governance require?",
            "options": [
                "Collect them now and decide later how to protect them",
                "Document a lawful, specific need and collect only what is necessary under applicable rules",
                "Collect them if the form includes a privacy link",
                "Store the numbers in a shared spreadsheet"
            ],
            "correct": 1,
            "explanation": "Data minimization and purpose limitation reduce risk. Confirm the purpose, legal basis, retention, and applicable jurisdiction before collection.",
            "source": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
            "source_label": "GDPR, Article 5"
        },
        {
            "id": "cl6",
            "difficulty": "advanced",
            "question": "A SaaS vendor proposes storing personal data in another country. What should the organization do before approving the change?",
            "options": [
                "Assume the vendor's location has no legal effect",
                "Have privacy and legal teams assess applicable transfer rules, contracts, safeguards, and data flows",
                "Move the data first and review the contract after launch",
                "Remove the vendor from the asset inventory"
            ],
            "correct": 1,
            "explanation": "Cross-border transfers can trigger jurisdiction-specific requirements. Review data flows, contract terms, safeguards, and applicable transfer mechanisms before the change.",
            "source": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
            "source_label": "GDPR, Chapter V"
        },
        {
            "id": "cl7",
            "difficulty": "beginner",
            "question": "Someone claiming to be law enforcement asks an employee to email customer records directly to a personal address. What should the employee do?",
            "options": [
                "Send the records immediately to avoid obstructing an investigation",
                "Preserve the request and route it to the organization's legal/privacy contact for verification and handling",
                "Delete the records before they can be requested formally",
                "Post the request in a public forum"
            ],
            "correct": 1,
            "explanation": "Verify and route legal demands through established procedures. Do not disclose records informally or destroy potentially relevant information; laws and process vary by jurisdiction.",
        },
        {
            "id": "cl8",
            "difficulty": "advanced",
            "question": "A manager asks you to test whether a competitor's login page has weak passwords. You have no written authorization. What should you do?",
            "options": [
                "Try only a few passwords because the test is for work",
                "Do not access or probe the system; request written authorization for any approved test",
                "Ask a colleague to test from a home network",
                "Use a personal account so the organization is not involved"
            ],
            "correct": 1,
            "explanation": "Security testing requires clear authorization and scope. Unauthorized access can have serious legal consequences; applicable law varies by jurisdiction.",
        }
    ],
    "governance": [
        {
            "id": "gov1",
            "difficulty": "beginner",
            "question": "A board asks how its organization should structure cybersecurity risk management. Which framework is designed to help organizations understand and improve that risk management?",
            "options": [
                "A structured cybersecurity risk-management framework",
                "A password list maintained by each department",
                "A one-time antivirus scan",
                "A public marketing calendar"
            ],
            "correct": 0,
            "explanation": "A cybersecurity risk-management framework helps an organization set strategy, assign roles, establish policy, and oversee security work.",
        },
        {
            "id": "gov2",
            "difficulty": "intermediate",
            "question": "A department buys a cloud tool that will process customer data without consulting security or privacy teams. What governance control is most useful?",
            "options": [
                "A risk-based supplier review before purchase, with documented ownership and contract safeguards",
                "A review only after the first incident",
                "A promise from the salesperson that the service is secure",
                "No review if the monthly cost is low"
            ],
            "correct": 0,
            "explanation": "Governance should account for supplier risk, data access, security expectations, incident reporting, and accountable ownership before adoption.",
        },
        {
            "id": "gov3",
            "difficulty": "beginner",
            "question": "A company cannot identify which laptops store regulated customer data. Which foundational governance activity should it prioritize?",
            "options": [
                "Inventory assets and data flows, assign owners, and identify business criticality",
                "Buy a new firewall without reviewing the environment",
                "Delete the asset register to avoid stale entries",
                "Let every employee create an independent inventory"
            ],
            "correct": 0,
            "explanation": "Risk decisions depend on knowing what assets and data exist, where they are, who owns them, and how important they are.",
        },
        {
            "id": "gov4",
            "difficulty": "intermediate",
            "question": "A patch cannot be applied to a critical server for two weeks because of a compatibility test. What is the best governance response?",
            "options": [
                "Ignore the issue because the patch is delayed",
                "Document an owner, assess exposure, apply interim controls, set an expiry, and track the exception to closure",
                "Disable all monitoring until the patch is ready",
                "Mark the risk resolved without evidence"
            ],
            "correct": 1,
            "explanation": "Time-bounded exceptions make residual risk visible and accountable while compensating controls and remediation are tracked.",
        },
        {
            "id": "gov5",
            "difficulty": "advanced",
            "question": "A risk assessment finds that a low-likelihood event could disrupt a critical service for days. How should leadership prioritize it?",
            "options": [
                "Ignore it because the likelihood is low",
                "Evaluate likelihood and impact against business priorities and documented risk tolerance",
                "Treat every risk as equally urgent",
                "Leave the decision to whichever team notices it first"
            ],
            "correct": 1,
            "explanation": "Risk treatment should consider both likelihood and impact, business context, dependencies, and the organization's approved risk tolerance.",
        },
        {
            "id": "gov6",
            "difficulty": "intermediate",
            "question": "Leadership approves a security exception for a business-critical legacy system. What should the approval include?",
            "options": [
                "A named risk owner, rationale, scope, compensating controls, review date, and exit plan",
                "Only a verbal agreement with no end date",
                "A waiver covering every system in the organization",
                "A request to stop recording the system's vulnerabilities"
            ],
            "correct": 0,
            "explanation": "An exception should be explicit, limited, time-bound, monitored, and owned by someone accountable for the residual risk.",
        },
        {
            "id": "gov7",
            "difficulty": "advanced",
            "question": "A security program reports only how many training sessions it held. Which measure would better inform leadership about risk reduction?",
            "options": [
                "A metric tied to an outcome, such as time to revoke access after an employee leaves or restore a critical service in an exercise",
                "The number of slides in the training deck",
                "The number of security acronyms used in policy",
                "The number of alerts closed without review"
            ],
            "correct": 0,
            "explanation": "Outcome-focused measures show whether controls work and support decisions; pair metrics with context rather than treating counts as proof of security.",
        },
        {
            "id": "gov8",
            "difficulty": "intermediate",
            "question": "A tabletop exercise reveals that nobody knows who can authorize shutting down a compromised service. What should the organization do next?",
            "options": [
                "Record the gap, assign an owner, clarify decision authority in the response plan, and retest it",
                "Keep the result confidential and make no changes",
                "Assume the incident commander will decide without documented authority",
                "Replace the exercise with a longer policy document"
            ],
            "correct": 0,
            "explanation": "Exercises should produce tracked improvements to roles, escalation, and decision-making; incident response is part of ongoing risk management.",
        }
    ]
}


_SUPPLEMENTAL_SCENARIOS = {
    "phishing": [
        ("A message claims your account will close unless you sign in using its link.", "Open the service through its known app or bookmarked address and check the account there."),
        ("An invoice arrives from a supplier, but the sender domain has an extra character.", "Verify the request using a known supplier contact, not the details in the message."),
        ("A familiar colleague unexpectedly asks you to buy gift cards urgently.", "Confirm the request through a separate, trusted communication channel."),
        ("A document attachment asks you to enable macros before it can be viewed.", "Do not enable macros; report the message and use an approved way to verify the document."),
        ("A delivery notice links to a page requesting a small payment and card details.", "Visit the carrier's official site directly and check the tracking number there."),
        ("An email asks you to approve an MFA prompt you did not initiate.", "Deny the prompt and report the unexpected authentication request immediately."),
        ("A QR code in an unexpected message leads to a sign-in page.", "Do not scan or sign in; navigate to the service independently and report the message."),
        ("A bank message asks you to call a number included in the email.", "Call the verified number on your card or official bank website."),
        ("A cloud-file share arrives from an unfamiliar sender with an urgent deadline.", "Verify the sender and sharing request through your organization's approved channel."),
        ("A message appears to come from an executive and requests confidential files.", "Validate the request and authorization with the executive through a separate channel."),
        ("A legitimate-looking login page has a misspelled domain name.", "Close it without entering credentials and report the suspicious URL."),
        ("A caller asks you to read a one-time sign-in code aloud.", "Never disclose the code; end the call and contact the organization using a trusted number."),
        ("An email thread suddenly contains new payment instructions.", "Verify the changed instructions with a previously known finance contact before paying."),
        ("A security alert asks you to install an attached cleanup tool.", "Do not run the attachment; report the alert and use approved security support."),
        ("Several coworkers receive the same suspicious campaign.", "Report one example through the approved channel so security staff can investigate and contain it.")
    ],
    "passwords": [
        ("A new account requires a password and you already use one similar elsewhere.", "Create a unique password for this account, preferably with an approved password manager."),
        ("You need to remember credentials for many work services.", "Store unique passwords in the organization's approved password manager."),
        ("A service reports that your password appeared in a breach.", "Change it promptly and change any reused instances on other services."),
        ("A colleague asks to borrow your account because theirs is unavailable.", "Do not share credentials; request an authorized individual account or access process."),
        ("A login supports passkeys or multifactor authentication.", "Enable the strongest supported phishing-resistant sign-in method available to you."),
        ("A password reset email arrives that you did not request.", "Do not use unexpected links; go directly to the service and review account security."),
        ("You have to create a memorable passphrase.", "Use several unrelated words and keep the passphrase unique to that account."),
        ("A shared spreadsheet contains team members' passwords.", "Remove the exposed secrets and move access to an approved identity and secrets system."),
        ("A developer needs an application credential for a service.", "Use a managed secret store and grant the credential only the permissions it needs."),
        ("An administrator account is used for routine browsing and email.", "Use a separate standard account for daily work and reserve the admin account for approved tasks."),
        ("A former employee's credentials may still work.", "Disable the account and revoke active sessions and credentials through the access process."),
        ("A password is stored in source code that was pushed to a repository.", "Revoke and rotate the exposed secret, then remove it from the repository history where feasible."),
        ("An account recovery question uses information visible on social media.", "Use a protected recovery method and avoid answers that can be publicly researched."),
        ("A service sends a one-time code after a login attempt you did not make.", "Do not share the code; deny the login and investigate the account activity."),
        ("A password manager offers to generate a long random password.", "Use the generated unique password and keep the vault protected with strong authentication.")
    ],
    "social-engineering": [
        ("A caller claims to be IT and asks you to install remote-access software.", "Verify the caller through the published IT helpdesk channel before taking action."),
        ("Someone follows you through a badge-controlled door without presenting a badge.", "Do not let them tailgate; follow site policy and direct them to reception or security."),
        ("A visitor says a senior manager sent them but is not on the visitor list.", "Verify their identity and authorization with the host before granting access."),
        ("A stranger asks you to hold a package while they enter a restricted area.", "Do not bypass access controls; ask security staff to handle the request."),
        ("A caller pressures you to reveal internal staff names and schedules.", "Decline to disclose internal information and report suspicious information gathering."),
        ("A supposed technician asks you to read a login code to prove your identity.", "Never share authentication codes; end the interaction and contact the real support team."),
        ("A vendor requests an exception to normal payment checks because of urgency.", "Use the documented approval and verification process regardless of the claimed urgency."),
        ("A person in a public place asks to use your unlocked work device briefly.", "Keep the device secured and direct them to an appropriate public resource."),
        ("A social-media message offers a reward for completing a work login survey.", "Do not enter work credentials; verify the survey with the organization independently."),
        ("A caller uses a familiar name but an unusual request and new phone number.", "Confirm the person's identity using a previously verified contact method."),
        ("A visitor tries to read documents left on a desk in a shared meeting room.", "Secure the documents and report unauthorized access according to local policy."),
        ("A requester asks you to bypass identity checks to restore access quickly.", "Follow the standard identity-verification process before changing account access."),
        ("An unknown person asks about your team's security tools and shift patterns.", "Share no operational details and notify your supervisor or security contact."),
        ("A direct message claims your account will be suspended unless you act immediately.", "Pause, verify the message through a known official channel, and report suspicious pressure tactics."),
        ("A colleague requests sensitive data from a personal email account.", "Verify identity and business need, then use an approved secure sharing method.")
    ],
    "data-protection": [
        ("A file contains personal information but has no sensitivity label.", "Apply the organization's classification rules and protect the file accordingly."),
        ("A report with customer details must be sent to a coworker.", "Share only the necessary data through an approved access-controlled channel."),
        ("A public link was accidentally enabled for a confidential document.", "Disable the public link, review access logs, and notify the data owner or security team."),
        ("A spreadsheet includes many columns irrelevant to the requested analysis.", "Remove unnecessary personal fields before sharing or processing the dataset."),
        ("A laptop containing sensitive records is being taken off-site.", "Use approved encryption and keep the device physically secured during transport."),
        ("A retention period for old customer records has expired.", "Dispose of the records securely under the approved retention schedule."),
        ("A coworker asks for access to a dataset unrelated to their role.", "Confirm a legitimate business need and grant only authorized, minimum access."),
        ("A data subject asks how their information is used.", "Route the request through the organization's privacy process and meet applicable deadlines."),
        ("A vendor requests a full production dataset for testing.", "Provide appropriately minimized or de-identified test data unless production data is specifically authorized."),
        ("A confidential printout is left at a shared printer.", "Retrieve it promptly and store or dispose of it according to its classification."),
        ("An employee emails sensitive information to the wrong recipient.", "Use available recall or containment steps and promptly report the disclosure for assessment."),
        ("A cloud folder has inherited access from a broad group.", "Review and narrow permissions to authorized users with a business need."),
        ("A portable drive containing regulated data is no longer needed.", "Use an approved secure sanitization or destruction process and document disposal."),
        ("A team plans to collect extra personal details just in case they become useful.", "Collect only the data needed for a defined, authorized purpose."),
        ("A data transfer crosses organizational or national boundaries.", "Check the approved transfer, privacy, and contractual requirements before sending it.")
    ],
    "safe-browsing": [
        ("A familiar website redirects you to a page asking for your work password.", "Check the exact domain and reach the service through a known bookmark instead."),
        ("A browser warns that a site's certificate is invalid.", "Do not bypass the warning; leave the site and verify the address or service status."),
        ("A pop-up says your computer is infected and gives a phone number.", "Close the pop-up without calling and use your approved security tools or support channel."),
        ("A website prompts you to install an unknown browser extension.", "Do not install it; use only reviewed extensions approved for your browser."),
        ("A search result advertises a download from an unfamiliar mirror site.", "Get software from the vendor's official source or an approved software catalog."),
        ("A page requests notification permissions without a clear need.", "Decline unnecessary permissions and review site permissions in browser settings."),
        ("A shortened link hides its destination in an unexpected message.", "Verify the sender and destination before opening; use a safe preview or approved inspection method."),
        ("A browser reports that an outdated plug-in is vulnerable.", "Update or remove the plug-in using trusted software update mechanisms."),
        ("A site asks you to sign in while you are using a public kiosk.", "Avoid entering sensitive credentials on a shared device; use a trusted personal device instead."),
        ("A web page asks you to paste a command into a terminal to fix an issue.", "Do not run commands from an untrusted page; verify with official documentation or IT."),
        ("A page requests access to your camera and microphone unexpectedly.", "Deny the permission and grant it only when required for a trusted, intended task."),
        ("A download has a file type different from what the site described.", "Do not open it; delete or report the unexpected file and verify the download source."),
        ("A browser session on a shared workstation remains signed in.", "Sign out, close the session, and clear locally stored data if required by policy."),
        ("A site uses HTTPS but has a suspicious misspelled domain.", "Treat the domain as suspicious; encryption does not prove the site is legitimate."),
        ("A browser has many old saved site permissions.", "Review and revoke permissions that are no longer needed.")
    ],
    "wifi-security": [
        ("A cafe Wi-Fi network has a name similar to the venue's official network.", "Confirm the exact network name with staff before connecting."),
        ("A public wireless network has no password and you need to access work files.", "Use the organization's approved VPN and avoid sensitive work if the connection is untrusted."),
        ("Your home router still uses its factory administrator password.", "Change it to a unique strong password and store it securely."),
        ("A router is configured with obsolete wireless encryption.", "Enable a currently supported WPA2-AES or WPA3 mode compatible with your devices."),
        ("A visitor needs internet access but not access to home devices.", "Provide a guest network isolated from trusted devices and internal resources."),
        ("A router's firmware has a security update available.", "Install the update through the vendor's verified management interface."),
        ("An unknown device appears on the home Wi-Fi network.", "Review the device and network credentials, then remove unauthorized access."),
        ("A public hotspot asks you to install a certificate to connect.", "Do not install an unverified certificate; confirm the requirement with the legitimate provider."),
        ("A Wi-Fi network uses the same password as your other accounts.", "Replace it with a unique network passphrase not reused elsewhere."),
        ("A router's remote administration is enabled without a business need.", "Disable internet-facing administration or restrict it to a secure management path."),
        ("A smart device must connect to your home network but should not reach computers.", "Place it on a segmented guest or IoT network where supported."),
        ("You need to send sensitive data while on an untrusted network.", "Use an approved encrypted connection and verify the destination service."),
        ("A coworker creates an unauthorized access point in the office.", "Report it to network or security staff so it can be investigated safely."),
        ("A wireless access point is no longer supported by its manufacturer.", "Replace it with supported equipment and migrate settings securely."),
        ("A router setup allows WPS with a weak PIN method.", "Disable WPS where it is not needed and use the router's stronger supported authentication.")
    ],
    "device-security": [
        ("A work laptop is missing the latest security patches.", "Install approved updates promptly and restart when required."),
        ("A phone is lost while its work email account is signed in.", "Report the loss immediately so the device can be located, locked, or wiped under policy."),
        ("A device is left unattended in a shared office.", "Lock the screen before leaving it unattended."),
        ("A USB drive of unknown origin is found in the parking lot.", "Do not connect it; hand it to security or IT for safe handling."),
        ("An app requests device permissions unrelated to its purpose.", "Deny unnecessary access and report the app if it is used for work."),
        ("A laptop's disk is not encrypted and contains work information.", "Enable organization-approved full-disk encryption and verify recovery arrangements."),
        ("A user wants to install software from an unofficial download site.", "Use the approved software catalog or verify the vendor source and authorization."),
        ("Endpoint protection reports malware on a work device.", "Follow the security team's isolation and reporting instructions; do not delete evidence."),
        ("A developer workstation runs with administrator rights for everyday work.", "Use a standard account for routine work and elevate only for approved tasks."),
        ("A device is being retired and still stores company files.", "Wipe or destroy storage using the approved secure disposal procedure."),
        ("A personal device is used to access company data.", "Use only approved BYOD controls, enrollment, and data-separation protections."),
        ("A device backup contains sensitive files but is not encrypted.", "Move backups to an approved encrypted service and protect their access."),
        ("A screen may be visible to people in a public location.", "Position the device to prevent shoulder surfing and avoid exposing sensitive data."),
        ("A security update fails repeatedly on an endpoint.", "Report the failure to IT and use the supported remediation process."),
        ("A browser stores an active session on a shared device.", "Sign out and avoid saving credentials or sessions on shared devices.")
    ],
    "incident-response": [
        ("You suspect a work device is infected with malware.", "Follow the incident plan to report and isolate the device without destroying evidence."),
        ("A staff member reports that credentials were entered on a fake page.", "Report it immediately and have the security team revoke sessions and reset credentials."),
        ("A service outage may be linked to a cyberattack.", "Use the incident escalation process and preserve relevant logs and timelines."),
        ("A customer reports receiving someone else's personal information.", "Escalate through the privacy and incident response channels without forwarding the data unnecessarily."),
        ("You find an unfamiliar process on a company endpoint.", "Record the observation and contact security staff; do not investigate beyond your authorization."),
        ("An incident team is unsure who can approve containment actions.", "Use the documented escalation authority and record decisions and approvals."),
        ("A suspected breach is discussed in a public chat room.", "Move incident coordination to the approved restricted channel and limit sensitive details."),
        ("A compromised account may still have active sessions.", "Revoke active sessions and credentials through the approved identity response process."),
        ("Responders need to preserve evidence from a device.", "Follow forensic procedures and maintain documented custody and handling."),
        ("A business unit wants to restart a suspected compromised server immediately.", "Coordinate recovery with incident leadership after containment and integrity checks."),
        ("A vendor may be involved in a security incident affecting your organization.", "Activate the supplier escalation and incident coordination process."),
        ("An incident response exercise identifies missing contact details.", "Assign an owner to update the contact list and verify it in the next exercise."),
        ("A security alert is confirmed as a false positive.", "Document the finding and tune detection carefully without suppressing valid future signals."),
        ("An incident appears contained but its root cause is unknown.", "Continue investigation and monitoring before declaring full recovery."),
        ("The incident is closed and stakeholders request a review.", "Document lessons learned, corrective actions, owners, and deadlines.")
    ],
    "cyber-law": [
        ("You discover a security flaw on a website you do not own.", "Do not access or alter data; use the owner's authorized vulnerability disclosure channel."),
        ("A manager asks you to inspect another employee's personal account.", "Decline unless there is clear legal authority and approved organizational authorization."),
        ("A security test is planned against a supplier's system.", "Obtain written scope and authorization from the system owner before testing."),
        ("A team wants to retain personal data longer than the stated purpose requires.", "Consult the privacy or legal function and follow applicable retention rules."),
        ("A legal hold applies to records scheduled for deletion.", "Suspend routine deletion for the covered records and follow legal instructions."),
        ("You receive a request from law enforcement for customer records.", "Refer the request to the organization's legal or privacy contact for validation and response."),
        ("A contractor's agreement does not describe incident notification duties.", "Escalate the contract gap for legal and security review before relying on the arrangement."),
        ("A security researcher reports a vulnerability under a disclosure policy.", "Route it through the authorized vulnerability handling process and respect its scope."),
        ("A team proposes copying licensed software without checking its terms.", "Verify license permissions with the appropriate legal or procurement process."),
        ("An employee accidentally accesses a record outside their permitted role.", "Stop accessing it and report the event through the privacy or security process."),
        ("A cross-border data transfer is planned for a new service.", "Obtain privacy and legal review of the applicable transfer requirements first."),
        ("A colleague wants to publish identifiable incident details online.", "Do not publish; obtain approval from legal, privacy, and incident leadership."),
        ("An organization receives a breach notification deadline under applicable law.", "Escalate promptly so qualified legal and privacy staff can assess obligations and timing."),
        ("A security test could disrupt a third-party service.", "Confirm explicit authorization, scope, timing, and safeguards with the system owner."),
        ("A team is unsure whether a monitoring activity is legally permitted.", "Pause the activity and seek advice from the organization's legal and privacy teams.")
    ],
    "governance": [
        ("A business unit has no named owner for a critical cyber risk.", "Assign an accountable risk owner and record treatment decisions and due dates."),
        ("A security policy has not been reviewed since the organization changed significantly.", "Schedule an owner-led review and update it to reflect current risks and responsibilities."),
        ("Leadership receives a dashboard with many technical counts but no risk context.", "Report decision-oriented measures tied to business outcomes and risk appetite."),
        ("A high-risk exception has no expiration date.", "Document an accountable approver, compensating controls, and a review or expiry date."),
        ("A new service is being launched without a security risk assessment.", "Include security and privacy risk review in the service's approval process."),
        ("A critical supplier cannot demonstrate required safeguards.", "Assess the risk, define remediation or compensating measures, and track accountable decisions."),
        ("A control repeatedly fails but nobody owns the remediation.", "Assign an owner, prioritize treatment, and monitor completion through governance."),
        ("Security objectives are disconnected from organizational priorities.", "Align the security program with business goals, risk appetite, and stakeholder responsibilities."),
        ("The organization has not tested its continuity assumptions.", "Exercise recovery plans and use measured results to improve resilience."),
        ("A board asks whether cyber risk is improving over time.", "Provide consistent trend measures, material changes, and residual risk against agreed tolerance."),
        ("A project requests a security exception without explaining the risk.", "Require a documented risk assessment and approval before granting any exception."),
        ("Audit findings recur across multiple departments.", "Identify systemic causes, assign accountable owners, and track corrective actions centrally."),
        ("A policy exists but staff do not know their responsibilities.", "Communicate role-specific responsibilities and verify understanding through training or exercises."),
        ("Risk decisions are made informally and cannot be traced.", "Maintain a risk register with rationale, accountable owners, treatment, and review dates."),
        ("A new regulation may affect the organization's control obligations.", "Assign qualified compliance review and map relevant obligations to accountable controls.")
    ],
    "cyber-threat-management": [
        ("A threat report describes attacks on a sector but no exposure assessment has been done.", "Compare the intelligence with the organization's assets, vulnerabilities, and business context before prioritizing action."),
        ("A critical vulnerability is public on an internet-facing system.", "Validate exposure, prioritize remediation by exploitability and impact, and track mitigation to closure."),
        ("An alert indicates suspicious access to a high-value account.", "Validate the signal, assess account impact, and follow the incident escalation process."),
        ("Threat intelligence contains indicators with no source or confidence level.", "Check provenance, confidence, and relevance before using the indicators for blocking decisions."),
        ("Several threat findings compete for a limited remediation budget.", "Rank them by likelihood, business impact, exposure, and available mitigations."),
        ("A business owner says a critical asset is missing from the inventory.", "Update asset ownership and criticality so threat and vulnerability decisions include it."),
        ("A new attack technique is reported but no control gap is known.", "Map the technique to existing defenses and identify testable gaps before selecting new controls."),
        ("A security team blocks an indicator but has not checked for prior activity.", "Search available telemetry for historical matches and investigate any affected systems."),
        ("A supplier discloses a security issue that may affect your environment.", "Identify dependent assets, obtain verified impact details, and coordinate risk treatment with the supplier."),
        ("A threat team receives many low-context alerts each day.", "Correlate alerts with asset criticality and threat context, then tune detection based on validated outcomes."),
        ("A mitigation could disrupt a critical business service.", "Coordinate risk-based containment with service owners and document the decision and safeguards."),
        ("A threat assessment has no assumptions, scope, or review date.", "Document its scope, evidence, assumptions, confidence, and conditions that trigger reassessment."),
        ("A tabletop exercise shows teams disagree on threat escalation criteria.", "Define severity thresholds, decision authority, and notification paths, then retest them."),
        ("A control was deployed but its effectiveness has not been measured.", "Test the control against relevant threat scenarios and track any remaining exposure."),
        ("A campaign appears to target the organization and peer companies.", "Coordinate intelligence sharing through trusted channels while protecting sensitive information.")
    ]
}


_DIFFICULTY_QUESTION_STEMS = {
    "beginner": "What is the safest next step?",
    "intermediate": "Which response best reduces the risk in this situation?",
    "advanced": "Which action should the security lead prioritize for this scenario?"
}

_TOPIC_EXPLANATION_RATIONALES = {
    "phishing": "Verifying through a separately trusted route prevents a message-controlled link, sender, or phone number from dictating where you authenticate or share information.",
    "passwords": "Unique, protected credentials and least privilege limit the damage caused by reuse, exposure, or inappropriate access.",
    "social-engineering": "Independent verification and established identity or physical-access controls prevent urgency or claimed authority from bypassing safeguards.",
    "data-protection": "Limiting access and using approved handling keeps sensitive information from being exposed or retained unnecessarily.",
    "safe-browsing": "Avoiding unverified sites and downloads reduces the chance of credential theft, malicious content, or unsafe data disclosure.",
    "wifi-security": "Using trusted network protections reduces exposure to interception, impersonation, and unauthorized access.",
    "device-security": "Managed protections and prompt containment reduce the impact of device compromise while preserving a reliable response path.",
    "incident-response": "Timely containment, evidence preservation, and escalation through established roles make incidents safer to investigate and resolve.",
    "cyber-law": "Documenting authority, scope, and handling decisions helps keep security work lawful, proportionate, and accountable.",
    "governance": "Clear ownership, reviewable decisions, and outcome-focused controls help leaders manage residual risk responsibly.",
    "cyber-threat-management": "Actions grounded in validated evidence, affected assets, and business impact avoid treating unconfirmed signals as established facts.",
}


def _add_minimum_difficulty_questions(minimum=15):
    used_choice_sets = {
        tuple(sorted(" ".join(option.casefold().split()) for option in question["options"]))
        for questions in QUESTIONS.values()
        for question in questions
    }
    for topic in QUIZ_TOPICS:
        topic_id = topic["id"]
        scenarios = _SUPPLEMENTAL_SCENARIOS[topic_id]
        topic_questions = QUESTIONS.setdefault(topic_id, [])
        for difficulty_index, difficulty in enumerate(_DIFFICULTY_QUESTION_STEMS):
            existing = sum(question["difficulty"] == difficulty for question in topic_questions)
            needed = max(0, minimum - existing)
            scenario_start = difficulty_index * 5
            for index in range(needed):
                scenario_index = (scenario_start + index) % len(scenarios)
                scenario, correct_option = scenarios[scenario_index]
                normalized_correct = " ".join(correct_option.casefold().split())
                candidate_answers = []
                seen_answers = {normalized_correct}
                for _, candidate in scenarios:
                    normalized_candidate = " ".join(candidate.casefold().split())
                    if normalized_candidate not in seen_answers:
                        seen_answers.add(normalized_candidate)
                        candidate_answers.append(candidate)
                distractor_sets = list(combinations(candidate_answers, 3))
                if not distractor_sets:
                    raise ValueError(f"Topic {topic_id} needs at least four distinct answer choices.")

                selected_distractors = None
                start = (difficulty_index * minimum + index) % len(distractor_sets)
                for offset in range(len(distractor_sets)):
                    distractors = distractor_sets[(start + offset) % len(distractor_sets)]
                    choice_set = tuple(sorted(
                        " ".join(option.casefold().split())
                        for option in (correct_option, *distractors)
                    ))
                    if choice_set not in used_choice_sets:
                        selected_distractors = distractors
                        used_choice_sets.add(choice_set)
                        break
                if selected_distractors is None:
                    raise ValueError(f"Topic {topic_id} has no unique answer-choice set remaining.")

                option_index = (index + len(topic_id) + len(difficulty)) % 4
                options = list(selected_distractors)
                options.insert(option_index, correct_option)
                question = {
                    "id": f"extra-{topic_id}-{difficulty}-{index + 1}",
                    "difficulty": difficulty,
                    "question": f"{scenario} {_DIFFICULTY_QUESTION_STEMS[difficulty]}",
                    "options": options,
                    "correct": option_index,
                    "explanation": (
                        f"{correct_option} {_TOPIC_EXPLANATION_RATIONALES[topic_id]}"
                    )
                }
                topic_questions.append(question)


_add_minimum_difficulty_questions()


def get_topics():
    return QUIZ_TOPICS


def get_questions(topic_id, difficulty=None, limit=None):
    questions = QUESTIONS.get(topic_id, [])
    if difficulty:
        questions = [q for q in questions if q["difficulty"] == difficulty]
    if limit:
        questions = questions[:limit]
    return questions


def get_all_questions():
    return QUESTIONS
