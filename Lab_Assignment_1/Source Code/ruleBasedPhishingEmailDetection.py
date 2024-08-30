import os
import re
from email import policy
from email.utils import parseaddr
from email.parser import BytesParser
import html2text
from rules import domainCheck, detectUrgentLanguage, checkMismatchedURLs, hasMaliciousAttachments, checkGrammarErrors

def parseEml(filePath):
    # Open and parse the .eml file
    with open(filePath, 'rb') as f:
        message = BytesParser(policy = policy.default).parse(f)

    # Extract the sender's email address
    senderName, senderEmailAddress = parseaddr(message['from'])
    
    # Extract the subject line
    subject = message['subject']
    
    # Initialize variables for email body and attachments
    bodyPlain = ""
    bodyHTML = ""
    attachments = []

    # Extract the email body (both plain text and HTML)
    if message.is_multipart():
        # Loop through the email parts
        for part in message.walk():
            contentType = part.get_content_type()
            contentDisposition = str(part.get("Content-Disposition"))
            
            # Extract plain text or HTML content
            if contentType == "text/plain" and "attachment" not in contentDisposition:
                bodyPlain += part.get_payload(decode = True).decode()  # Decode bytes to string
            elif contentType == "text/html" and "attachment" not in contentDisposition:
                bodyHTML += part.get_payload(decode = True).decode()  # Decode bytes to string
                
            # Extract attachments
            elif "attachment" in contentDisposition:
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
    else:
        # If not multipart, extract the payload directly
        body = message.get_payload(decode = True).decode()
    
    if bodyPlain != "":
        finalBody = bodyPlain
    elif bodyHTML != "":
        finalBody = html2text.html2text(bodyHTML)
    else:
        finalBody = body

    urls = re.findall(r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+', finalBody)
    
    return senderEmailAddress, subject, finalBody, urls, attachments

def phishingDetection(emailID, subject, body, urls, attachments):
    # Define weights for each rule
    weights = {
        'domainCheck': 0.3,
        'detectUrgentLanguage': 0.2,
        'checkMismatchedURLs': 0.2,
        'hasMaliciousAttachments': 0.25,
        'checkGrammarErrors': 0.05
    }
    
    # Rule 1: Domain Check
    validTLD, validDomain = domainCheck(emailID)
    domainCheckScore = 0
    if validTLD == 0 or validDomain == 0:
        domainCheckScore = 1  # Higher score means more likely to be phishing
    
    # Rule 2: Detect Urgent Language
    urgentSubject, urgentBody = detectUrgentLanguage(subject, body, None)
    urgentLanguageScore = urgentSubject or urgentBody
    
    # Rule 3: Check Mismatched URLs
    mismatchedURLsScore = 1 if checkMismatchedURLs(emailID, urls) else 0
    
    # Rule 4: Check for Malicious Attachments
    maliciousAttachmentsScore = 1 if hasMaliciousAttachments(attachments) else 0
    
    # Rule 5: Check Grammar Errors
    grammarErrorsScore = 1 if checkGrammarErrors(body) else 0

    if (domainCheckScore):
        print("Not from a whitelisted domain.")
    if (urgentLanguageScore):
        print("Urgent language found.")
    if (mismatchedURLsScore):
        print("Mismatching URLs found.")
    if (maliciousAttachmentsScore):
        print("Dangerous attachment extensions found.")
    if (grammarErrorsScore):
        print("Poorly written email.")
    print("-----------------------------------------------------------")
    
    # Calculate the weighted score
    phishingScore = (
        weights['domainCheck'] * domainCheckScore +
        weights['detectUrgentLanguage'] * urgentLanguageScore +
        weights['checkMismatchedURLs'] * mismatchedURLsScore +
        weights['hasMaliciousAttachments'] * maliciousAttachmentsScore +
        weights['checkGrammarErrors'] * grammarErrorsScore
    )
    
    # Phishing threshold - This can be adjusted based on testing
    threshold = 0.45
    
    # Determine if the email is likely phishing
    isPhishing = (round(phishingScore, 2) >= threshold)

    print("Details of the result")
    print("=====================")
    print(f"Phishing Score: {phishingScore:.2f}")
    print(f"Email is {'phishing' if isPhishing else 'not phishing'}.")

    return isPhishing

def evaluateSystem(testFolderPath, actualLabels):
    files = sorted([f for f in os.listdir(testFolderPath) if f.endswith('.eml')])

    TP, TN, FP, FN = 0, 0, 0, 0

    for i, file in enumerate(files):
        filePath = os.path.join(testFolderPath, file)
        emailID, subject, body, urls, attachments = parseEml(filePath)
        result = phishingDetection(emailID, subject, body, urls, attachments)

        if result and actualLabels[i] == 1:
            TP += 1
        elif not result and actualLabels[i] == 0:
            TN += 1
        elif result and actualLabels[i] == 0:
            FP += 1
        elif not result and actualLabels[i] == 1:
            FN += 1

    accuracy = (TP + TN) / (TP + TN + FP + FN)
    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0

    print()
    print("Final Result")
    print("------------")
    print(f"True Positives (TP): {TP}")
    print(f"True Negatives (TN): {TN}")
    print(f"False Positives (FP): {FP}")
    print(f"False Negatives (FN): {FN}")
    print(f"Accuracy: {accuracy:.2f}")
    print(f"True Positive Rate (TPR): {TPR:.2f}")
    print(f"False Positive Rate (FPR): {FPR:.2f}")


folderPath = "C:\\myFolder\\DUK\\Lab\\AI for Cyber Sec\\Dataset"
actualLabels = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]  # Labels where 0 is not phishing, and 1 is phishing for your test samples
evaluateSystem(folderPath, actualLabels)