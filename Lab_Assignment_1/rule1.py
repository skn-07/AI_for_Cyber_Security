import tldextract

def ruleNo1(emailId):
    legitimateTLD = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'co', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'ru', 'cn', 'in', 'io', 'ai', 'app', 'dev', 'tech', 'eu', 'io', 'cloud', 'online', 'store']
    
    legitimateDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'yandex.com', 'paypal.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'apple.com', 'google.com', 'duk.ac.in']

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
