import os
import requests
import json
import pandas as pd
import os.path
import csv
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek
from langchain_groq import ChatGroq
from langchain.agents import AgentExecutor, create_react_agent

from langchain import hub
prompt_react = hub.pull("hwchase17/react")


# Define paths for datasets
labeled_data_path = os.path.join(os.path.dirname(__file__), "Labled.csv")
raw_data_path = os.path.join(os.path.dirname(__file__), "Raw.csv")

# Hardcoded few-shot examples in case data files are not found
hardcoded_examples = """
Example 1:
URL: software-secure.com/album/
Status: 1

Example 2:
URL: https://amacon.servicevq-jp.com/lg/
Status: 0

Example 3:
URL: tech.groups.yahoo.com/group/opengl-gamedev-l/
Status: 1

Example 4:
URL: http://www.epioscard-verify.top/
Status: 0
"""

# Try to load datasets, use hardcoded examples if files not found
try:
    if os.path.exists(labeled_data_path) and os.path.exists(raw_data_path):
        labeled_data = pd.read_csv(labeled_data_path)
        raw_data = pd.read_csv(raw_data_path)
        
        labeled_data = labeled_data.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Prepare few-shot examples
        few_shot_examples = labeled_data
        few_shot_prompt = "\n".join(
            f"URL: {row['Url']}\nStatus: {row['Status']}" for _, row in few_shot_examples.iterrows()
        )
    else:
        few_shot_prompt = hardcoded_examples
except Exception as e:
    print(f"Error loading datasets: {str(e)}. Using default examples.")
    few_shot_prompt = hardcoded_examples

class DeepSeekFewShot:
    def __init__(self):
        self.api_key = os.environ.get('DEEPSEEK_API_KEY')
        self.api_url = "https://api.deepseek.com/v1/chat/completions"
        
    def classify_url(self, url):
        """
        Classifies a URL using DeepSeek AI with few-shot prompting technique.
        Returns a tuple of (classification, confidence, details)
        where classification is 'safe' or 'malicious'
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        deepseek_llm = ChatDeepSeek(model="deepseek-chat",temperature=0)
        query = """
        You are a cybersecurity expert. Classify the URL as 1 (legitimate) or 0 (malicious) based on patterns.

        Examples:
        {few_shot_prompt}

        Rules:
        1. Analyze domain structure and TLD carefully. Be wary of domain spoofing like 'facebook-login.com' or 'youtube.suspicious-domain.com' or 'youtube.in' (instead of youtube.com).
        2. Country-specific TLDs (like .in, .ru, .cn) that are attached to well-known brands should be treated suspiciously unless the brand is known to operate in that country.
        3. Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords.
        4. Return ONLY 0 or 1 with no explanation.

        URL to classify: {url}
        """.format(url=url,few_shot_prompt=few_shot_prompt)
        react_agent = create_react_agent(deepseek_llm, prompt=prompt_react, tools = [])
        react_agent_executor = AgentExecutor(
        agent=react_agent, handle_parsing_errors=True,tools = []
        )

        
        
        try:
            result = react_agent_executor.invoke({"input":query})
            output = int(result["output"].strip())                    
                    
            if output == 1:
                return "safe", 0.88, f"The URL appears to be legitimate based on its structure and characteristics."
            elif output == 0:
                return "malicious", 0.93, f"The URL shows signs of being malicious, including suspicious patterns in its structure."
            else:
                return "uncertain", 0.5, f"Could not determine URL safety. Treating as potentially malicious."
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
            
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        # Simple logic to simulate classification
        suspicious_keywords = ['verify', 'login', 'secure', 'account', 'bank', 'paypal', 'update', 'confirm']
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml']
        
        # Check for IP address URLs (often suspicious)
        import re
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            return "malicious", 0.88, f"Demo Mode: This URL contains an IP address instead of a domain name, which is often associated with phishing attempts. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in suspicious_tlds):
            return "malicious", 0.86, f"Demo Mode: This URL uses a TLD often associated with malicious sites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious keywords in URL
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            return "malicious", 0.78, f"Demo Mode: This URL contains suspicious keywords often found in malicious URLs. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for extremely long URLs or ones with lots of special characters
        if len(url) > 100 or url.count('%') > 3:
            return "malicious", 0.75, f"Demo Mode: This URL is unusually long or contains many encoded characters, which can be a sign of obfuscation. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for reputable domains
        reputable_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com']
        if any(domain in url.lower() for domain in reputable_domains):
            return "safe", 0.92, f"Demo Mode: This URL appears to be from a reputable domain. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default behavior based on URL length and complexity
        if len(url) < 30 and url.count('.') <= 2 and url.count('/') <= 3:
            return "safe", 0.65, f"Demo Mode: This URL has a simple structure typical of legitimate sites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default to uncertain
        return "uncertain", 0.5, f"API key not configured. Running in demo mode with limited functionality. This is a placeholder response."


class ChatGPTFewShot:
    def __init__(self):
        self.api_key = os.environ.get('OPENAI_API_KEY')
        self.api_url = "https://api.openai.com/v1/chat/completions"
        
    def classify_url(self, url):
        """
        Classifies a URL using ChatGPT API with few-shot prompting technique.
        Returns a tuple of (classification, confidence, details)
        where classification is 'safe' or 'malicious'
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        openai_llm = ChatOpenAI(model_name="gpt-3.5-turbo", openai_api_key=self.api_key)
        query = """
        You are a cybersecurity expert. Classify the URL as 1 (legitimate) or 0 (malicious) based on patterns.

        Examples:
        {few_shot_prompt}

        Rules:
        1. Analyze domain structure and TLD carefully. Be wary of domain spoofing like 'facebook-login.com' or 'youtube.suspicious-domain.com' or 'youtube.in' (instead of youtube.com).
        2. Country-specific TLDs (like .in, .ru, .cn) that are attached to well-known brands should be treated suspiciously unless the brand is known to operate in that country.
        3. Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords.
        4. Return ONLY 0 or 1 with no explanation.

        URL to classify: {url}
        """.format(url=url,few_shot_prompt=few_shot_prompt)
        react_agent = create_react_agent(openai_llm, prompt=prompt_react, tools = [])
        react_agent_executor = AgentExecutor(
        agent=react_agent, handle_parsing_errors=True,tools = []
        )

        
        
        try:
            result = react_agent_executor.invoke({"input":query})
            output = int(result["output"].strip())                    
                    
            if output == 1:
                return "safe", 0.88, f"The URL appears to be legitimate based on its structure and characteristics."
            elif output == 0:
                return "malicious", 0.93, f"The URL shows signs of being malicious, including suspicious patterns in its structure."
            else:
                return "uncertain", 0.5, f"Could not determine URL safety. Treating as potentially malicious."
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
    
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        # Create demo classifier using the same logic as DeepSeekFewShot but with slight variations
        suspicious_keywords = ['login', 'password', 'bank', 'account', 'verify', 'wallet', 'crypto', 'confirm']
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.buzz']
        
        # Check for subdomains with numbers
        import re
        numeric_subdomain = re.compile(r'https?://[a-z]*\d+[a-z]*\.')
        if numeric_subdomain.search(url.lower()):
            return "malicious", 0.91, f"Demo Mode: This URL contains numeric patterns in the subdomain, which is often associated with automatically generated phishing domains. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for IP address URLs
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            return "malicious", 0.93, f"Demo Mode: This URL uses an IP address instead of a domain name, which is a common characteristic of phishing sites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in suspicious_tlds):
            return "malicious", 0.89, f"Demo Mode: This URL uses a TLD that is frequently associated with malicious websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious keywords
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            return "malicious", 0.85, f"Demo Mode: This URL contains terms commonly found in phishing attempts. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for long URLs with many special characters
        if len(url) > 120 or url.count('%') > 2 or url.count('&') > 3:
            return "malicious", 0.82, f"Demo Mode: This URL is unusually long or contains many special characters, which may indicate obfuscation. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for reputable domains
        reputable_domains = ['google.', 'microsoft.', 'apple.', 'amazon.', 'github.', 'wikipedia.', 'twitter.', 'linkedin.']
        if any(domain in url.lower() for domain in reputable_domains):
            return "safe", 0.95, f"Demo Mode: This URL appears to be from a well-established and reputable domain. Without API keys, we're using basic heuristics to classify URLs."
        
        # Additional check for education or government domains
        if '.edu' in url.lower() or '.gov' in url.lower():
            return "safe", 0.94, f"Demo Mode: This URL belongs to an educational or government domain, which are generally trustworthy. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default behavior based on URL characteristics
        if len(url) < 35 and url.count('.') <= 2 and url.count('/') <= 3:
            return "safe", 0.72, f"Demo Mode: This URL has a relatively simple structure characteristic of legitimate websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default to uncertain
        return "uncertain", 0.5, f"API key not configured. Running in demo mode with limited functionality. This is a placeholder response." 

class GeminiFewShot:    
    def __init__(self):
        self.api_key = os.environ.get('GEMINI_API_KEY')
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "models/gen-lang-client-0424570342-87f29e2566a1.json"
        
    def classify_url(self, url):
        """
        Classifies a URL using Google's Gemini API with few-shot prompting technique.
        Returns a tuple of (classification, confidence, details)
        where classification is 'safe' or 'malicious'
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        
        gemini_llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash-001",
        temperature=0
        )
        query = """
        You are a cybersecurity expert. Classify the URL as 1 (legitimate) or 0 (malicious) based on patterns.

        Examples:
        {few_shot_prompt}

        Rules:
        1. Analyze domain structure and TLD carefully. Be wary of domain spoofing like 'facebook-login.com' or 'youtube.suspicious-domain.com' or 'youtube.in' (instead of youtube.com).
        2. Country-specific TLDs (like .in, .ru, .cn) that are attached to well-known brands should be treated suspiciously unless the brand is known to operate in that country.
        3. Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords.
        4. Return ONLY 0 or 1 with no explanation.

        URL to classify: {url}
        """.format(url=url,few_shot_prompt=few_shot_prompt)
        react_agent = create_react_agent(gemini_llm, prompt=prompt_react, tools = [])
        react_agent_executor = AgentExecutor(
        agent=react_agent, handle_parsing_errors=True,tools = []
        )

        
        
        try:
            result = react_agent_executor.invoke({"input":query})
            output = int(result["output"].strip())                    
                    
            if output == 1:
                return "safe", 0.88, f"The URL appears to be legitimate based on its structure and characteristics."
            elif output == 0:
                return "malicious", 0.93, f"The URL shows signs of being malicious, including suspicious patterns in its structure."
            else:
                return "uncertain", 0.5, f"Could not determine URL safety. Treating as potentially malicious."
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
            
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        # Create a different set of heuristics from the other models
        suspicious_keywords = ['verify', 'account', 'login', 'bank', 'secure', 'update', 'confirm', 'wallet']
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.buzz', '.work']
        
        # Check for IP address URLs
        import re
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            return "malicious", 0.91, f"Demo Mode (Gemini): This URL uses an IP address instead of a domain name, which is often associated with phishing sites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for extremely long domain names or path components
        parts = url.split('/')
        if any(len(part) > 30 for part in parts):
            return "malicious", 0.87, f"Demo Mode (Gemini): This URL contains unusually long components that may be attempting to obfuscate its true nature. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in suspicious_tlds):
            return "malicious", 0.88, f"Demo Mode (Gemini): This URL uses a TLD often associated with malicious websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious keywords
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            return "malicious", 0.79, f"Demo Mode (Gemini): This URL contains terms commonly found in phishing attempts. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for many subdomains
        if url.count('.') > 3:
            return "malicious", 0.76, f"Demo Mode (Gemini): This URL has an unusual number of subdomains, which can be a sign of malicious intent. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for reputable domains
        reputable_domains = ['google.', 'microsoft.', 'apple.', 'amazon.', 'github.', 'linkedin.', 'twitter.']
        if any(domain in url.lower() for domain in reputable_domains):
            return "safe", 0.93, f"Demo Mode (Gemini): This URL appears to be from a well-established and reputable domain. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for education or government domains
        if '.edu' in url.lower() or '.gov' in url.lower():
            return "safe", 0.92, f"Demo Mode (Gemini): This URL belongs to an educational or government domain, which are generally trustworthy. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default behavior based on URL characteristics
        if len(url) < 30 and url.count('.') <= 2 and url.count('/') <= 2:
            return "safe", 0.74, f"Demo Mode (Gemini): This URL has a simple structure typical of legitimate websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default to uncertain
        return "uncertain", 0.5, f"API key not configured. Running in demo mode with limited functionality. This is a placeholder response from Gemini model." 

class LlamaFewShot:
    def __init__(self):
        self.api_key = os.environ.get('GROQ_API_KEY')
        
    def classify_url(self, url):
        """
        Classifies a URL using Llama model from Hugging Face with few-shot prompting technique.
        Returns a tuple of (classification, confidence, details)
        where classification is 'safe' or 'malicious'
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
        
        try:    
            # Initialize Hugging Face endpoint for Llama model
            llama_llm = ChatGroq(temperature=0, groq_api_key=self.api_key, model_name="meta-llama/llama-4-scout-17b-16e-instruct")
            
            # Create prompt template
            query = """
            You are a cybersecurity expert. Classify the URL as 1 (legitimate) or 0 (malicious) based on patterns.

            Examples:
            {few_shot_prompt}

            Rules:
            1. Analyze domain structure and TLD carefully. Be wary of domain spoofing like 'facebook-login.com' or 'youtube.suspicious-domain.com' or 'youtube.in' (instead of youtube.com).
            2. Country-specific TLDs (like .in, .ru, .cn) that are attached to well-known brands should be treated suspiciously unless the brand is known to operate in that country.
            3. Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords.
            4. Use few shot prompt provided to you to classify the URL.
            5. Return ONLY 0 or 1 with no explanation.
            6. Don't use any tools.
            7. In the last Case, Use your own knowledge to classify the URL.

            URL to classify: {url}
            """.format(url=url,few_shot_prompt=few_shot_prompt)
            react_agent = create_react_agent(llama_llm, prompt=prompt_react, tools = [])
            react_agent_executor = AgentExecutor(
            agent=react_agent, handle_parsing_errors=True,tools = [], verbose=True
            )

            result = react_agent_executor.invoke({"input":query})
            output = int(result["output"].strip())
            if output == 1:
                return "safe", 0.88, f"The URL appears to be legitimate based on its structure and characteristics."
            elif output == 0:
                return "malicious", 0.93, f"The URL shows signs of being malicious, including suspicious patterns in its structure."
            else:
                return "uncertain", 0.5, f"Could not determine URL safety. Treating as potentially malicious."
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
            
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        # Create a unique set of heuristics for Llama model
        suspicious_keywords = ['verify', 'secure', 'login', 'account', 'bank', 'wallet', 'password', 'update']
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.work', '.click']
        
        # Check for long subdomains with random characters (potential phishing)
        import re
        random_pattern = re.compile(r'https?://[a-z0-9]{10,}\.')
        if random_pattern.search(url.lower()):
            return "malicious", 0.92, f"Demo Mode (Llama): This URL contains an unusually long or random subdomain, which is often associated with phishing attempts. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for IP address URLs
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            return "malicious", 0.94, f"Demo Mode (Llama): This URL uses an IP address instead of a domain name, which is frequently associated with malicious sites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for URLs with many dots (subdomains)
        if url.count('.') > 4:
            return "malicious", 0.82, f"Demo Mode (Llama): This URL has an excessive number of subdomains, which is uncommon for legitimate websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in suspicious_tlds):
            return "malicious", 0.85, f"Demo Mode (Llama): This URL uses a TLD that is frequently associated with low-cost domains often used for malicious purposes. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious keywords in URL
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            return "malicious", 0.83, f"Demo Mode (Llama): This URL contains terms commonly found in phishing websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for encoded characters
        if url.count('%') > 2:
            return "malicious", 0.81, f"Demo Mode (Llama): This URL contains multiple encoded characters, which can be used to obfuscate malicious URLs. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for trusted domains
        trusted_domains = ['google.', 'microsoft.', 'apple.', 'amazon.', 'github.', 'youtube.', 'linkedin.']
        if any(domain in url.lower() for domain in trusted_domains):
            return "safe", 0.94, f"Demo Mode (Llama): This URL appears to be from a well-established and reputable domain. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for educational or government domains
        if '.edu' in url.lower() or '.gov' in url.lower() or '.org' in url.lower():
            return "safe", 0.91, f"Demo Mode (Llama): This URL belongs to an educational, governmental, or organizational domain, which are generally trustworthy. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default behavior for simple URLs
        if len(url) < 40 and url.count('.') <= 2 and url.count('/') <= 2:
            return "safe", 0.78, f"Demo Mode (Llama): This URL has a simple structure characteristic of legitimate websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default to uncertain
        return "uncertain", 0.5, f"API key not configured. Running in demo mode with limited functionality. This is a placeholder response from Llama model." 