import re
import requests
import os
import base64
import json
from fuzzywuzzy import fuzz, process
from bs4 import BeautifulSoup

# EMAIL EXTRATCION

def extract_field(pattern, content):
    match = re.search(pattern, content)
    if match:
        return match.group(1)
    else:
        return None

def extract_body_text(body_html):
    soup = BeautifulSoup(email_content, 'html.parser')
    body_tag = soup.find('body')
    if body_tag:
        plain_text = body_tag.get_text(separator='\n', strip=True)
        return plain_text
    else:
        return None

def extract_domain(email_address):
    match = re.search(r'@([^>]+)', email_address)
    if match:
        return match.group(1)
    else:
        return None

def extract_email_from_header(header):
    match = re.search(r'<([^>]+)>', header)
    if match:
        return match.group(1)
    else:
        return header.strip()


# Define the regular expression patterns
regex_pattern1 = r'@([a-z]+[01]([01])?[a-z]+|[a-z]+\-[a-z]+[01]([01])?[a-z]+)'
regex_pattern2 = r'@\w+\-(com|biz|org|net)\.\w{2,3}'
regex_pattern3 = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

# Compile the regular expressions
regex1 = re.compile(regex_pattern1)
regex2 = re.compile(regex_pattern2)
regex3 = re.compile(regex_pattern3)


#  VirusTotal Domain: functions 

def get_domain_report(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {"x-apikey": "0fb372a95f4f19b0a82f1e5ad306e4241ee0cbf377a5d8843db8c67cb100fae8"}
    response = requests.get(url, headers=headers)
    return response.json()

def extract_domain_info(data):
    # Extracting required information
    registrar = data.get('data', {}).get('attributes', {}).get('registrar', None)
    total_votes = data.get('data', {}).get('attributes', {}).get('total_votes', None)
    last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', None)
    reputation = data.get('data', {}).get('attributes', {}).get('reputation', None)
  
    return {
        'registrar': registrar,
        'total_votes': total_votes,
        'last_analysis_stats': last_analysis_stats,
        'reputation': reputation
    }
    
def format_info(data):
    formatted_info = ""
    for key, value in data.items():
        if isinstance(value, dict):
            formatted_info += f"{key}:\n"
            for sub_key, sub_value in value.items():
                formatted_info += f"  {sub_key}: {sub_value}, "
            formatted_info = formatted_info.rstrip(', ') + "\n"  # Remove the trailing comma and add newline
        else:
            formatted_info += f"{key}: {value}\n"
    return formatted_info

#  VirusTotal URL: functions 

def get_url_report(url):
    url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    headers = {"x-apikey": "0fb372a95f4f19b0a82f1e5ad306e4241ee0cbf377a5d8843db8c67cb100fae8"}
    response = requests.get(url, headers=headers)
    return response.json()

def encode_url(input_url):
    url_id = base64.urlsafe_b64encode(input_url.encode()).decode().strip("=")
    return url_id

def extract_url_info(data):
    last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', None)
    total_votes = data.get('data', {}).get('attributes', {}).get('total_votes', None)
    keywords = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('keywords', None)
    og_locale = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('og:locale', None)
    og_image_type = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('og:image:type', None)
    facebook_domain_verification = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('facebook-domain-verification', None)
    og_url = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('og:url', None)
    og_site_name = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('og:site_name', None)
    description = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('description', None)
    og_type = data.get('data', {}).get('attributes', {}).get('html_meta', {}).get('og:type', None)
    
    return {
        'last_analysis_stats': last_analysis_stats,
        'total_votes': total_votes,
        'keywords': keywords,
        'og_locale': og_locale,
        'og_image_type': og_image_type,
        'facebook_domain_verification': facebook_domain_verification,
        'og_url': og_url,
        'og_site_name': og_site_name,
        'description': description,
        'og_type': og_type
    }


def test_regex(pattern, input_text):
    match = pattern.search(input_text)
    return match

def test_phishing_domains(input_text):
    with open('datasets/phishing_domains.txt', 'r') as file:
        dataset = file.read().splitlines()
        return any(item in input_text for item in dataset)

def test_phishing_attachments(input_text):
    with open('datasets/malicious_attachments.txt', 'r') as file:
        dataset = file.read().splitlines()
        return any(item in input_text for item in dataset)

def test_phishing_links(input_text):
    with open('datasets/phishing_links.txt', 'r') as file:
        dataset = file.read().splitlines()
        return any(item in input_text for item in dataset)

def test_phishing_words(input_text):
    with open('datasets/phishing _words.txt', 'r') as file:
        dataset = file.read().splitlines()
        return any(item in input_text for item in dataset)

def test_similar_domains(input_text):
    similar_domains = []
    with open('datasets/custom_domains.txt', 'r') as file:
        dataset = file.read().splitlines()
        input_parts = input_text.split('.')
        if len(input_parts) >= 2:
            input_domain = input_parts[-2]  # Get the domain without TLD
            for item in dataset:
                item_parts = item.split('.')
                if len(item_parts) >= 2:
                    item_domain = item_parts[-2]  # Get the domain without TLD
                    similarity_score = fuzz.ratio(item_domain, input_domain)
                    if similarity_score >= 90:
                        similar_domains.append(item)

    return similar_domains

   
def analyze_email(email):
    result1 = test_regex(regex1, email)
    result2 = test_regex(regex2, email)
    return result1, result2

def analyze_domain(domain):
    result3 = test_regex(regex3, domain)
    return result3


print("Welcome to the Email Analsysis Tool!")

while True:
    print("\nOptions:")
    print("1. Email Analysis")
    print("2. Quit")

    user_option = input("Please select an option (1-2): ")
    
    if user_option == '1':
        # Define the path to the 'emails' folder
        folder_path = 'emails'

        # List all files in the 'emails' folder
        files = os.listdir(folder_path)

        # Display the list of files to the user
        print("Available files:")
        for i, file in enumerate(files, 1):
            print(f"{i}. {file}")

        # Prompt the user to choose a file
        choice = input("\nEnter the number of the file you want to analyze: ")

        # Validate the user's choice
        try:
            choice = int(choice)
            if 1 <= choice <= len(files):
                filename = files[choice - 1]
                file_path = os.path.join(folder_path, filename)

                # Read email content from the chosen text file
                with open(file_path, 'r') as file:
                    email_content = file.read()
            else:
                print("Invalid choice. Please enter a valid number.")
                continue  # Continue to the next iteration of the loop
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue  # Continue to the next iteration of the loop
        except Exception as e:
            print(f"An error occurred: {e}")
            continue 
        
                # Extract header 
        header_from = extract_field(r'From: (.+)', email_content)
        header_reply_to = extract_field(r'Reply-To: (.+)', email_content)

        # Extract subject
        subject = extract_field(r'Subject: (.+)', email_content)

        # Extract body
        body_match = re.search(r'<body>(.+?)</body>', email_content, re.DOTALL)
        body_html = body_match.group(1).strip() if body_match else None
        body_text = extract_body_text(body_html)

        # Extract URLs (limit to the first three)
        urls = re.findall(r'<a href="([^"]+)"', email_content)[:3]

        # Extract attachments
        attachments = re.findall(r'Content-Disposition: attachment; filename="([^"]+)"', email_content)

        # Check for DKIM, DMARC, and SPF pass
        dkim_pass = 'dkim=pass' in email_content
        dmarc_pass = 'dmarc=pass' in email_content
        spf_pass = 'spf=pass' in email_content

        # Extract email addresses
        from_email = extract_email_from_header(header_from)
        reply_to_email = extract_email_from_header(header_reply_to) if header_reply_to else None

        from_domain = extract_domain(from_email)
        reply_to_domain = extract_domain(reply_to_email) if reply_to_email else None

        # Extract Spam Score
        spam_score_match = re.search(r'SpamScore: (\d+)', email_content)
        spam_score = int(spam_score_match.group(1)) if spam_score_match else None

        # Compare Reply-To and From domains
        same_domain = from_domain == reply_to_domain if reply_to_domain else None
        

        # Print the extracted information about email address  sender
        print(f"\nEmail Details-")
        print(f"\nFrom Email: {from_email}")
            
        # Results from the email regex 
        result1, result2 = analyze_email(from_email)
        if result1:
            print(f"\nResults from email regex: This may be a typo-squatting domain.")
        elif result2:
            print(f"\nResults from email regex: This may have double top-level domains.")
        else:
            print(f"\nResults from email regex: Did not match, email address is safe from typo-squatting and double top-level domains.")
            
        if reply_to_email:
            print(f"\nReply-To Email: {reply_to_email}")
            # Results from the email regex 
            result3, result4 = analyze_email(reply_to_email)
            if result3:
                print(f"\nResults from email regex: This may be a typo-squatting domain.")
            elif result4:
                print(f"\nResults from email regex: This may have double top-level domains.")
            else:
                print(f"\nResults from email regex: Did not match, email address is safe from typo-squatting and double top-level domains.")
            
        # Print Reply-To and From domain comparison
        if same_domain is not None:
            print(f"\nReply-To and From domains are {'the same. This means the email is from the legitimate sender' if same_domain else 'different. As they are different it means that this email may be forged'}.")        
        
        # Domain printing 
        print(f"\nFrom Domain: {from_domain}")
        
        #Test 1: regex
        result5 = analyze_domain(from_domain)
        if result5:
            print(f"\nResult: This is a valid domain name.")
        else:
            print(f"\nDid not match, domain may be unsafe.") 
            
        #Test 2: Dataset 1 
        domain_set1 = test_phishing_domains(from_domain)
        if domain_set1:
            print(f"\nResult: This may contain a phishing domain.")
        else:
            print(f"\nNo match found, input is likely safe from phishing domains.")
            
        #Test 3; Dataset 2 
        domain_dataset1 = test_similar_domains(from_domain)
        
        if domain_dataset1:
            print(f"\nResult: This may domain is apart of disposal domains. Similar ones are:")
            for domain in domain_dataset1:
                print(domain)
        else:
            print(f"\nNo match found, input is not apart of the disposal domains.")
            
         #Test 4: Virus Total
        domain_report1 = get_domain_report(from_domain)
        domain_info1 = extract_domain_info(domain_report1)
        formatted_info1 = format_info(domain_info1)
        print(f"\nDOMAIN REPORT:")
        print(formatted_info1)
        
        if reply_to_domain:
            print(f"Reply-To Domain: {reply_to_domain}")
            
            #Test 1: regex
            result6 = analyze_domain(reply_to_domain)
            if result6:
                print(f"\nResult: This is a valid domain name.")
            else:
                print(f"\nDid not match, domain may be unsafe.") 
                
            #Test 2: Dataset 1 
            domain_set2 = test_phishing_domains(reply_to_domain)
            if domain_set2:
                print(f"\nResult: This may contain a phishing domain.")
            else:
                print(f"\nNo match found, input is likely safe from phishing domains.")
                
            #Test 3; Dataset 2 
            domain_dataset2 = test_similar_domains(reply_to_domain)
            
            if domain_dataset2:
                print(f"\nResult: This may domain is apart of disposal domains. Similar ones are:")
                for domain in domain_dataset2:
                    print(domain)
            else:
                print(f"\nNo match found, input is not apart of the disposal domains.")
                
                
            #Test 4: Virus Total Domain
            domain_report2 = get_domain_report(reply_to_domain)
            domain_info2 = extract_domain_info(domain_report2)
            formatted_info2 = format_info(domain_info2)
            print(f"\nDOMAIN REPORT 2:")
            print(formatted_info2)        
            
            
            
        #Print text about subject and test  
        print(f"Subject: {subject or 'Not found'}")
        subject_test = test_phishing_words(subject)
        
        if subject_test:
            print(f"\nPhishing words Result: This may contain phishing-related words.")
        else:
            print(f"\nNo match found, input is likely safe from phishing words.")
            
         #Print text about body and test
        print(f"Body:\n{body_text or 'Not found'}")
        body_test = test_phishing_words(body_text)
        
        if body_test:
            print(f"\n Phishing words Result: This contains phishing-related words.")
        else:
            print(f"\nNo match found, input is likely safe from phishing-related words.")
        
        
        print(f"\nURLs:")
        for url in urls:
            print(url)
            
            #Test virus total 
            url_id = encode_url(url)
            url_report = get_url_report(url_id)
            url_info = extract_url_info(url_report)
            formatted_info = format_info(url_info)
            print(f"\nURL REPORT:")
            print(formatted_info)
        if not urls:
            print(f"No URLs found")
        
        
    
        print("\nAttachments:")
        for attachment in attachments:
            print(attachment)
            attachment_result = test_phishing_attachments(attachment)  
            if attachment_result:
                    print(f"\nResult: This may attachment type is used in phihsing attacks.")
            else:
                    print(f"\nNo match found, input is likely safe attachment.")   
        if not attachments:
            print(f"No attachments found")
            
            

        # Print DKIM, DMARC, and SPF pass results
        print(f"\nDKIM: {'Pass' if dkim_pass else 'Fail'}")
        print(f"DMARC: {'Pass' if dmarc_pass else 'Fail'}")
        print(f"SPF: {'Pass' if spf_pass else 'Fail'}")

        # Print Spam Score
        if spam_score is not None:
            print(f"\nSpam Score: {spam_score}")
            if spam_score > 50:
                print("\nThis email is likely spam")

    
    elif user_option == '2':
        break
    
    else:
        print("\nInvalid option. Please select 1-2.")

print("Goodbye!")

