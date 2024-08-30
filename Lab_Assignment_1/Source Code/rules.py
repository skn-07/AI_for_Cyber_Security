import tldextract
import re

# Rule 1
def domainCheck(emailId):
    legitimateTLD = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'co', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'ru', 'cn', 'in', 'io', 'ai', 'app', 'dev', 'tech', 'eu', 'ac.in', 'io', 'cloud', 'online', 'store']
    
    legitimateDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'yandex.com', 'paypal.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'apple.com', 'google.com', 'duk.ac.in', 'spotify.com', 'hackthebox.com', 'tryhackme.com', 'tenable.com', 'kaggle.com']

    extract = tldextract.extract(emailId)
    if extract.suffix:
        domain = extract.domain + '.' + extract.suffix
    else:
        domain = extract.domain
    
    validTLD = 0
    if extract.suffix.lower() in legitimateTLD:
        validTLD = 1

    validDomain = 0
    if domain.lower() in legitimateDomains:
        validDomain = 1
    
    return validTLD, validDomain

# Rule 2
def detectUrgentLanguage(emailSubject, emailBody, urgentPhrases):
    urgentPhrasesRegex = [
        # Urgent Action Needed
        r"immediate.*action.*required",
        r"act.*now.*before.*it's.*too.*late",
        r"urgent[:;,-]?.*your.*account.*has.*been.*compromised",
        r"your.*account.*is.*about.*to.*be.*suspended",
        r"immediate.*review.*of.*your.*account",
        r"update.*your.*account.*information",
        r"suspicious.*activity.*detected",
        r"action.*needed[:;,-]?.*confirm.*your.*identity",
        r"unusual.*login.*attempt",
        r"urgent[:;,-]?.*update.*your.*payment.*information",
        r"confirm.*your.*account.*now",
        r"reset.*your.*password.*now",
        r"you.*have.*24.*hours.*to.*respond",
        r"your.*account.*needs.*verification",
        r"failure.*to.*act.*will.*result.*in.*loss",
        r"your.*data.*will.*be.*deleted",
        r"action.*required",

        # Security Alerts and Threats
        r"your.*account.*has.*been.*hacked",
        r"unauthorized.*access.*detected",
        r"your.*personal.*information.*is.*at.*risk",
        r"legal.*action.*will.*be.*taken",
        r"you.*are.*at.*risk.*of.*identity.*theft",
        r"security.*alert[:;,-]?.*unusual.*login.*attempt",
        r"malware.*detected.*in.*your.*account",
        r"your.*private.*information.*is.*exposed",

        # Financial Threats
        r"your.*payment.*is.*overdue",
        r"payment.*declined",
        r"billing.*issue.*detected",
        r"urgent[:;,-]?.*update.*your.*payment.*information",
        r"your.*payment.*failed",
        r"final.*warning[:;,-]?.*pay.*now.*to.*avoid.*penalties",
        r"action.*required[:;,-]?.*update.*billing.*information",
        r"your.*bank.*account.*is.*locked",
        r"immediate.*payment.*required",
        r"your.*account.*will.*be.*locked",

        # Prize Winnings and Offers
        r"claim.*your.*prize.*now",
        r"congratulations[:;,-]?.*you've.*been.*selected",
        r"you've.*won.*a.*prize",
        r"exclusive.*access",
        r"one[-.]*time.*opportunity",
        r"limited.*time.*offer",
        r"free.*gift.*for.*you",
        r"special.*promotion.*just.*for.*you",
        r"hurry[:;,-]?.*offer.*expires.*soon",
        r"act.*fast.*to.*claim",

        # Time-Sensitive and Last Chance Warnings
        r"final.*notice",
        r"last.*chance",
        r"this.*is.*your.*last.*chance",
        r"time[-.]*sensitive",
        r"don't.*delay",
        r"hurry[!.,]?",
        r"offer.*expires.*soon",
        r"last.*day.*to.*claim",

        # Suspicious Requests
        r"please.*verify.*your.*identity",
        r"download.*the.*attached.*document",
        r"open.*the.*attachment.*for.*details",
        r"click.*the.*link.*to.*avoid.*deactivation",
        r"verify.*your.*account.*immediately",
        r"login.*now.*to.*avoid.*suspension",
        r"update.*your.*details.*now",

        # Fear-Inducing Phrases
        r"you.*have.*been.*reported",
        r"your.*computer.*is.*infected",
        r"your.*privacy.*is.*at.*risk",
        r"your.*security.*has.*been.*compromised",
        r"we.*detected.*a.*problem.*with.*your.*account",
        r"legal.*action.*will.*be.*taken.*if.*ignored",
        r"your.*account.*has.*been.*frozen",

        # General Phishing Indicators
        r"do.*not.*ignore.*this.*message",
        r"important[:;,-]?.*read.*immediately",
        r"action.*required[:;,-]?.*verify.*your.*email",
        r"urgent[:;,-]?.*open.*immediately",
        r"act.*fast",
        r"account.*alert",
        r"notice.*of.*breach",
        r"failure.*to.*respond.*will.*result.*in",
        r"verify.*your.*details.*now"
    ]

    urgentPhraseinSubject = 0
    urgentPhraseinBody = 0
    for pattern in urgentPhrasesRegex:
        if re.search(pattern, emailSubject, re.IGNORECASE):
            print(f"Phishing phrase detected in subject with pattern: {pattern}")
            urgentPhraseinSubject = 1
        elif re.search(pattern, emailBody, re.IGNORECASE):
            print(f"Phishing phrase detected in body with pattern: {pattern}")
            urgentPhraseinBody = 1
    
    return urgentPhraseinSubject, urgentPhraseinBody

# Rule 3
def checkMismatchedURLs(sender, links):
    senderDomain = sender.split('@')[-1]
    for link in links:
        if senderDomain not in link:
            return True
    return False

# Rule 4
def hasMaliciousAttachments(attachments):
    dangerousFileExtensions = [
    ".exe", ".app", ".apk", ".bin", ".com", ".zip", ".rar", ".7z", ".tar", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".scr", ".js", ".vbs", ".bat"
    ]
    for attachment in attachments:
        if any(attachment.lower().endswith(ext) for ext in dangerousFileExtensions):
            return True
    return False

#Rule 5
def checkGrammarErrors(body):
    # Common grammatical errors patterns
    commonErrors = {
        r"\byour\b(?!')": "you're",  # Check for misuse of "your" instead of "you're"
        r"\bthere\b": "they're|their",  # Check for misuse of "there"
        r"\bits\b(?!')": "it's",  # Check for misuse of "its" instead of "it's"
        r"\bthen\b": "than",  # "then" vs "than"
        r"\bto\b": "too|two",  # "to" vs "too" vs "two"
        r"\baffect\b": "effect",  # "affect" vs "effect"
        r"\baccept\b": "except",  # "accept" vs "except"
        r"\blose\b": "loose",  # "lose" vs "loose"
        r"\bcould\b": "should|would",  # "could" vs "should" vs "would"
        r"\bwhether\b": "weather",  # "whether" vs "weather"
        r"\bwho\b": "whom",  # "who" vs "whom"
        r"\bwhich\b": "witch",  # "which" vs "witch"
        r"\bhear\b": "here",  # "hear" vs "here"
        r"\bknow\b": "no",  # "know" vs "no"
        r"\bone\b": "won",  # "one" vs "won"
        r"\bpare\b": "pear",  # "pare" vs "pear"
        r"\bpeace\b": "piece",  # "peace" vs "piece"
        r"\bpour\b": "poor",  # "pour" vs "poor"
        r"\bright\b": "write",  # "right" vs "write"
        r"\bsea\b": "see",  # "sea" vs "see"
        r"\bso\b": "sow",  # "so" vs "sow"
        r"\bsome\b": "sum",  # "some" vs "sum"
        r"\bsteal\b": "steel",  # "steal" vs "steel"
        r"\btail\b": "tale",  # "tail" vs "tale"
        r"\bwear\b": "where",  # "wear" vs "where"
        r"\bweek\b": "weak",  # "week" vs "weak"
        r"\bdon't\b": "do not",  # "don't" vs "do not"
        r"\bcan't\b": "cannot",  # "can't" vs "cannot"
        r"\bwon't\b": "will not",  # "won't" vs "will not"
        r"\bshouldn't\b": "should not",  # "shouldn't" vs "should not"
        r"\bwouldn't\b": "would not",  # "wouldn't" vs "would not"
        r"\bcouldn't\b": "could not",  # "couldn't" vs "could not"
        r"\bhasn't\b": "has not",  # "hasn't" vs "has not"
        r"\bhavent't\b": "have not",  # "haven't" vs "have not"
        r"\baren't\b": "are not",  # "aren't" vs "are not"
        r"\bweren't\b": "were not",  # "weren't" vs "were not"
        r"\bisn't\b": "is not",  # "isn't" vs "is not"
        r"\bdoesn't\b": "does not",  # "doesn't" vs "does not"
    }

    # Count the number of errors found in the text
    errorCount = 0
    
    # Convert body to lowercase to make search case insensitive
    body = body.lower()

    # Check for each common error
    for wrong, correct in commonErrors.items():
        if re.search(wrong, body):
            errorCount += 1

    # Threshold for identifying poorly written emails
    threshold = 5  # Adjust this threshold as needed
    
    if errorCount >= threshold:
        return True  # Poorly written
    else:
        return False  # Not poorly written
