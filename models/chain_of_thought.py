import os
import requests
import json
import re

class DeepSeekChainOfThought:
    def __init__(self):
        self.api_key = os.environ.get('DEEPSEEK_API_KEY')
        self.api_url = "https://api.deepseek.com/v1/chat/completions"
        
    def classify_url(self, url):
        """
        Classifies a URL using DeepSeek API with chain-of-thought prompting technique.
        Returns a tuple of (classification, confidence, details)
        where classification is 'safe' or 'malicious'
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        prompt = f"""
        You are a cybersecurity expert. Analyze this URL and determine if it's legitimate or malicious.

        URL: {url}

        Think step by step:
        1. Analyze the domain name, TLD, and overall URL structure
        2. Check for suspicious patterns like random characters, misleading domains, or unusual TLDs
        3. Consider if the URL tries to imitate a well-known website
        4. Assess if the URL contains suspicious keywords or patterns
        5. Provide your reasoning and conclusion

        Then classify the URL as 1 (legitimate) or 0 (malicious).
        Start your response with "Analysis:" followed by your reasoning.
        End with "Classification: [0 or 1]"
        """
        
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0
            }
            
            response = requests.post(self.api_url, headers=headers, data=json.dumps(data))
            
            if response.status_code != 200:
                return "uncertain", 0.5, f"API Error: {response.text}"
                
            result = response.json()
            output = result["choices"][0]["message"]["content"].strip()
            print(output)
            
            # Extract classification and analysis
            classification_match = re.search(r"Classification:\s*(\d)", output)
            print(classification_match)
            analysis = output.split("Classification:")[0].replace("Analysis:", "").strip()
            
            if classification_match:
                classification = classification_match.group(1)
                if classification == "1":
                    return "safe", 0.88, analysis
                else:
                    return "malicious", 0.94, analysis
            else:
                return "uncertain", 0.5, "Could not determine classification from model output."
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
            
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        import re
        import random
        
        # Demo mode will provide more detailed analysis to simulate chain-of-thought
        analysis = "Demo Mode Analysis (without API keys):\n\n"
        
        # Calculate a score based on various heuristics
        score = 0
        suspicious_points = []
        safety_points = []
        
        # Check for IP address URLs
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            score += 30
            suspicious_points.append("The URL uses an IP address instead of a domain name, which is often used in phishing sites to hide the true destination.")
            
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.buzz']
        for tld in suspicious_tlds:
            if tld in url.lower():
                score += 15
                suspicious_points.append(f"The URL uses the TLD '{tld}' which is frequently associated with low-cost or free domains often used for malicious purposes.")
                break
                
        # Check for suspicious subdomains with random-looking characters
        random_subdomain = re.compile(r'https?://[a-z0-9]{8,}\.')
        if random_subdomain.search(url.lower()):
            score += 20
            suspicious_points.append("The subdomain contains a long string of seemingly random characters, which is commonly seen in automatically generated phishing domains.")
            
        # Check for suspicious keywords
        suspicious_keywords = ['login', 'password', 'bank', 'account', 'verify', 'wallet', 'crypto', 'confirm', 'secure']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                score += 10
                suspicious_points.append(f"The URL contains the term '{keyword}', which is commonly used in phishing URLs to create a sense of urgency or legitimacy.")
                
        # Check for URL length
        if len(url) > 100:
            score += 15
            suspicious_points.append("The URL is unusually long, which can be a sign of obfuscation or attempt to hide the true destination.")
            
        # Check for excessive use of special characters
        special_chars = ['%', '&', '@', '!', '#', '$']
        special_char_count = sum(url.count(char) for char in special_chars)
        if special_char_count > 5:
            score += 15
            suspicious_points.append(f"The URL contains an unusually high number of special characters ({special_char_count}), which may indicate obfuscation.")
            
        # Check for reputable domains
        reputable_domains = ['google.', 'microsoft.', 'apple.', 'amazon.', 'github.', 'wikipedia.', 'twitter.', 'linkedin.']
        for domain in reputable_domains:
            if domain in url.lower():
                score -= 40
                safety_points.append(f"The URL contains reference to '{domain}' which is a well-established and reputable domain.")
                break
                
        # Check for education or government domains
        if '.edu' in url.lower():
            score -= 30
            safety_points.append("The URL belongs to an educational institution domain (.edu), which is generally trustworthy.")
        if '.gov' in url.lower():
            score -= 35
            safety_points.append("The URL belongs to a government domain (.gov), which is generally trustworthy.")
            
        # Check for simple structure typical of legitimate sites
        if len(url) < 50 and url.count('.') <= 2 and url.count('/') <= 3 and special_char_count < 2:
            score -= 20
            safety_points.append("The URL has a relatively simple structure with few subdomains and path components, which is characteristic of many legitimate websites.")
            
        # Build detailed analysis
        if suspicious_points:
            analysis += "Suspicious characteristics:\n"
            for i, point in enumerate(suspicious_points, 1):
                analysis += f"{i}. {point}\n"
                
        if safety_points:
            analysis += "\nSafety indicators:\n"
            for i, point in enumerate(safety_points, 1):
                analysis += f"{i}. {point}\n"
                
        # Make classification decision based on score
        analysis += f"\nWithout API keys, I'm using heuristic analysis. "
        
        if score > 30:
            confidence = min(0.5 + (score/100), 0.95)  # Cap confidence at 0.95
            return "malicious", confidence, analysis + f"Based on the above analysis, this URL appears to be malicious. (Demo mode score: {score})"
        elif score < -10:
            confidence = min(0.5 + (abs(score)/100), 0.95)  # Cap confidence at 0.95
            return "safe", confidence, analysis + f"Based on the above analysis, this URL appears to be legitimate. (Demo mode score: {score})"
        else:
            return "uncertain", 0.5, analysis + f"Based on basic heuristics, I cannot confidently classify this URL without API access. (Demo mode score: {score})\n\nAPI key not configured. Running in demo mode with limited functionality."


class ChatGPTChainOfThought:
    def __init__(self):
        self.api_key = os.environ.get('OPENAI_API_KEY')
        self.api_url = "https://api.openai.com/v1/chat/completions"
        
    def classify_url(self, url):
        """
        Classifies a URL using ChatGPT API with chain-of-thought prompting technique.
        Returns a tuple of (classification, confidence, details)
        where classification is 'safe' or 'malicious'
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        prompt = f"""
        You are a cybersecurity expert. Analyze this URL and determine if it's legitimate or malicious.

        URL: {url}

        Think step by step:
        1. Analyze the domain name, TLD, and overall URL structure
        2. Check for suspicious patterns like random characters, misleading domains, or unusual TLDs
        3. Consider if the URL tries to imitate a well-known website
        4. Assess if the URL contains suspicious keywords or patterns
        5. Provide your reasoning and conclusion

        Then classify the URL as 1 (legitimate) or 0 (malicious).
        Start your response with "Analysis:" followed by your reasoning.
        End with "Classification: [0 or 1]"
        """
        
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0
            }
            
            response = requests.post(self.api_url, headers=headers, data=json.dumps(data))
            
            if response.status_code != 200:
                return "uncertain", 0.5, f"API Error: {response.text}"
                
            result = response.json()
            output = result["choices"][0]["message"]["content"].strip()
            
            # Extract classification and analysis
            classification_match = re.search(r"Classification:\s*(\d)", output)
            analysis = output.split("Classification:")[0].replace("Analysis:", "").strip()
            
            if classification_match:
                classification = classification_match.group(1)
                if classification == "1":
                    return "safe", 0.92, analysis
                else:
                    return "malicious", 0.97, analysis
            else:
                return "uncertain", 0.5, "Could not determine classification from model output."
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
    
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        import re
        
        # Similar to DeepSeekChainOfThought but with slightly different analysis
        analysis = "Demo Mode Analysis (without API keys):\n\n"
        
        # Calculate a score based on various heuristics but with a different algorithm
        score = 0
        suspicious_points = []
        safety_points = []
        
        # Detailed domain analysis
        domain_parts = url.split('//')[-1].split('/')[0].split('.')
        
        # Check if domain mimics a well-known domain with slight variation
        well_known_domains = [
            'google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal', 
            'netflix', 'twitter', 'instagram', 'linkedin', 'github'
        ]
        
        # Check for typosquatting (e.g., 'g00gle' instead of 'google')
        for domain in well_known_domains:
            typo_pattern = re.compile(f"{domain[0]}[o0]{domain[2:]}", re.IGNORECASE)
            if any(typo_pattern.search(part) for part in domain_parts):
                score += 40
                suspicious_points.append(f"The domain appears to be typosquatting a well-known domain (similar to '{domain}'). This is a common phishing technique.")
                
        # Check for URL shorteners
        shortener_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        if any(service in url.lower() for service in shortener_services):
            score += 10
            suspicious_points.append("The URL uses a shortening service, which can hide the true destination and is sometimes used to mask malicious URLs.")
        
        # Check for excessive subdomains
        if len(domain_parts) > 3:
            score += 15
            suspicious_points.append(f"The URL has an unusually high number of subdomains ({len(domain_parts)}), which can be suspicious.")
            
        # Check for IP address URLs
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            score += 35
            suspicious_points.append("The URL uses an IP address instead of a domain name, which is a common characteristic of phishing sites trying to hide their identity.")
            
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.buzz', '.work']
        tld = domain_parts[-1] if domain_parts else ""
        if f'.{tld.lower()}' in suspicious_tlds:
            score += 20
            suspicious_points.append(f"The URL uses the TLD '.{tld}' which is frequently associated with malicious sites due to its low cost or free registration.")
                
        # Check for suspicious keywords in path or query
        path_parts = url.split('/')
        query_parts = url.split('?')[-1] if '?' in url else ""
        path_and_query = ' '.join(path_parts + [query_parts]).lower()
        
        suspicious_keywords = ['login', 'password', 'bank', 'account', 'verify', 'wallet', 'crypto', 'confirm', 'secure', 'update']
        for keyword in suspicious_keywords:
            if keyword in path_and_query:
                score += 15
                suspicious_points.append(f"The URL path or query parameters contain the term '{keyword}', which is commonly used in phishing URLs.")
                break
                
        # Check for excessive query parameters
        if query_parts and query_parts.count('&') > 5:
            score += 10
            suspicious_points.append(f"The URL contains an unusually high number of query parameters ({query_parts.count('&') + 1}), which can be used to obfuscate the true intent.")
            
        # Check for reputable domains
        reputable_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'wikipedia.org']
        domain_string = '.'.join(domain_parts)
        for domain in reputable_domains:
            if domain_string.lower() == domain:
                score -= 50
                safety_points.append(f"The URL domain '{domain_string}' is a well-established and reputable domain.")
                break
                
        # Check for education or government domains
        if domain_string.lower().endswith('.edu'):
            score -= 35
            safety_points.append("The URL belongs to an educational institution domain (.edu), which is generally trustworthy.")
        if domain_string.lower().endswith('.gov'):
            score -= 40
            safety_points.append("The URL belongs to a government domain (.gov), which is generally trustworthy.")
            
        # Check for HTTPS usage
        if url.lower().startswith('https://'):
            score -= 5
            safety_points.append("The URL uses HTTPS, which provides encryption and indicates some level of security (though malicious sites can also use HTTPS).")
            
        # Build detailed analysis
        if suspicious_points:
            analysis += "Suspicious characteristics:\n"
            for i, point in enumerate(suspicious_points, 1):
                analysis += f"{i}. {point}\n"
                
        if safety_points:
            analysis += "\nSafety indicators:\n"
            for i, point in enumerate(safety_points, 1):
                analysis += f"{i}. {point}\n"
                
        # Add conclusion
        analysis += f"\nWithout API keys, I'm using heuristic analysis. "
        
        if score > 35:
            confidence = min(0.5 + (score/100), 0.96)  # Cap confidence at 0.96
            return "malicious", confidence, analysis + f"Based on the above factors, this URL shows multiple concerning patterns typical of malicious sites. (Demo mode score: {score})"
        elif score < -15:
            confidence = min(0.5 + (abs(score)/100), 0.96)  # Cap confidence at 0.96
            return "safe", confidence, analysis + f"Based on the above factors, this URL appears to be from a legitimate source. (Demo mode score: {score})"
        else:
            return "uncertain", 0.5, analysis + f"Based on basic heuristics, I cannot confidently classify this URL without API access. (Demo mode score: {score})\n\nAPI key not configured. Running in demo mode with limited functionality." 