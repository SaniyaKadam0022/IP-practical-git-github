def is_suspicious_url(url):

    score = 0
    reasons = []                #keeps track of why points were added

    #Checks suspicious words in the url
    suspicious_words = ["login", "verify", "password", "account", "secure", "signin", "update", "confirm", "bank", "security", "payment"]
    for word in suspicious_words:
        if word in url:
            score += 1
            reasons.append(f"Contains suspicious word: '{word}'")

    #Checks if Dot count is greater than 3
    if url.count(".") > 3:
        score += 2
        reasons.append("URL has too many dots (more than 3)")

    #IP address detection
    parts = url.split(".")          #splits the url where dot is present
    numeric_parts = 0

    for part in parts:
        if part.isdigit():
            numeric_parts += 1

    if numeric_parts >= 4:          #checks if numeric count is greater than equal to 4
        score += 2
        reasons.append("URL host looks like a raw IP address")

    #Checks for known url shorteners
    known_shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "shorte.st", "adf.ly"]
    for shortener in known_shorteners:
        if shortener in url:
            score += 2
            reasons.append(f"Uses known URL shortener: '{shortener}'")

    #Checks for @ symbol in url
    if "@" in url:
        score += 3
        reasons.append("URL contains '@' symbol (can hide real destination)")

    #Checks if url length is too long
    if len(url) > 75:
        score += 1
        reasons.append(f"URL is unusually long ({len(url)} characters)")

    #Checks for too many hyphens in url
    if url.count("-") > 2:
        score += 1
        reasons.append("Domain contains multiple hyphens")

    #Checks for extra // after the scheme
    if "//" in url[8:]:
        score += 2
        reasons.append("URL contains a suspicious extra '//' (possible redirect trick)")

    #Convert score into a verdict label
    if score >= 4:
        result = "Highly Suspicious"
    elif score >= 2:
        result = "Suspicious"
    else:
        result = "Likely Safe"

    return score, result, reasons        #return score, verdict, and reasons list


#Take URL input from the user
user_url = input("Enter a URL to check: ")

#Run the check and unpack the returned score, result, and reasons
score, result, reasons = is_suspicious_url(user_url)

#Display the outcome
print("\n--- URL Check Report ---")
print(f"Entered URL   : {user_url}")
print(f"Suspicion Score: {score}")
print(f"Verdict        : {result}")

if reasons:
    print("Reasons flagged:")
    for reason in reasons:
        print(f" - {reason}")
else:
    print("No suspicious signals detected.")