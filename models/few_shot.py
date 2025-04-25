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
from langchain.agents import AgentExecutor, create_react_agent, create_structured_chat_agent, create_openai_tools_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
# Import DuckDuckGo search tool
from langchain_community.tools import DuckDuckGoSearchRun
from langchain.tools.base import StructuredTool
from langchain.pydantic_v1 import BaseModel, Field
from typing import List
from langchain import hub
from langchain.prompts import PromptTemplate
from langchain.agents.format_scratchpad import format_to_openai_functions
from langchain.agents.output_parsers import OpenAIFunctionsAgentOutputParser
prompt_react = hub.pull("hwchase17/react")

# Define a custom search tool based on DuckDuckGo
class SearchURLInfo(BaseModel):
    """Input for the search tool."""
    query: str = Field(..., description="The URL or domain to search information about")

# Create a wrapper around DuckDuckGo search specifically for URL info
class URLSearchTool:
    def __init__(self):
        self._search = DuckDuckGoSearchRun()
        
    def search_url_info(self, query: str) -> str:
        """Search for information about a URL or domain using DuckDuckGo."""
        search_query = f"information about website {query} safety reputation domain"
        try:
            results = self._search.run(search_query)
            return results
        except Exception as e:
            return f"Error performing search: {str(e)}"
            
    def get_tool(self):
        """Return a StructuredTool that can be used in a LangChain agent."""
        return StructuredTool.from_function(
            func=self.search_url_info,
            name="search_url_info",
            description="Searches for information about a URL or domain's safety, reputation, and background.",
            args_schema=SearchURLInfo,
            return_direct=False
        )

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
        Analyzes a URL using DeepSeek AI with improved structure.
        Returns detailed security analysis of the URL.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        # Initialize DeepSeek model
        deepseek_llm = ChatDeepSeek(model="deepseek-chat", temperature=0)
        
        # Use direct approach rather than ReAct agent framework
        prompt = f"""You are a cybersecurity expert. Analyze this URL carefully and determine if it's legitimate or malicious.

URL to analyze: {url}

Previous URL classification examples:
{few_shot_prompt}

Please provide your analysis in the following structured format:
---
## Domain Analysis
[Analyze the domain structure, TLD, and any suspicious patterns]

## Security Concerns
[List potential security issues, if any]

## Recommendation
[Provide your recommendation about visiting this site]

## CONCLUSION
This URL is [MALICIOUS/SAFE] - choose one definitively

## Classification
[0 or 1] (where 0 = malicious, 1 = safe)
---

Important guidelines:
1. Be especially vigilant about domain spoofing (like 'facebook-login.com' or 'youtube.in')
2. Country-specific TLDs (.in, .ru, .cn) with well-known brands should be treated suspiciously
3. Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords
4. Provide a clear, definitive conclusion without uncertainty
"""
        
        try:
            # Direct model invocation without agent framework
            response = deepseek_llm.invoke(prompt).content
            
            # Extract classification and conclusion
            classification_match = re.search(r"## Classification\s*\n\s*(\d)", response, re.IGNORECASE)
            conclusion_match = re.search(r"## CONCLUSION\s*\n\s*This URL is (MALICIOUS|SAFE)", response, re.IGNORECASE)
            
            if classification_match:
                output = int(classification_match.group(1))
                
                if output == 1:
                    return "safe", 0.88, response
                elif output == 0:
                    return "malicious", 0.93, response
                else:
                    return "uncertain", 0.5, response
            elif conclusion_match:
                conclusion = conclusion_match.group(1).upper()
                if conclusion == "SAFE":
                    return "safe", 0.85, response
                else:
                    return "malicious", 0.9, response
            else:
                # Additional fallback logic
                if "SAFE" in response.upper() and "MALICIOUS" not in response.upper():
                    return "safe", 0.75, response
                elif "MALICIOUS" in response.upper():
                    return "malicious", 0.8, response
                else:
                    return "uncertain", 0.5, response
                
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
        self.url_search = URLSearchTool()
        
    def classify_url(self, url):
        """
        Analyzes a URL using ChatGPT API with web search capabilities.
        Returns detailed analysis information about the URL.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_analyze(url)
            
        # Extract domain for searching
        try:
            if '//' in url:
                domain = url.split('//')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
        except:
            domain = url
            
        # Use OpenAI with tool calling which is more reliable than ReAct format
        openai_llm = ChatOpenAI(model_name="gpt-4o", openai_api_key=self.api_key, temperature=0)
        
        # Create tools list with our search tool
        search_tool = self.url_search.get_tool()
        tools = [search_tool]
        
        # Create a prompt suitable for OpenAI tools agent
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity expert analyzing URLs for potential threats.
You have access to search tools to gather information about URLs and domains.
Always provide a clear, definitive conclusion about whether a URL is malicious or safe."""),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        
        # Create an OpenAI tools agent instead of a ReAct agent
        agent = create_openai_tools_agent(openai_llm, tools, prompt)
        
        agent_executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=5
        )
        
        # Create the query for the agent
        query = f"""I need to analyze this URL: {url}
        
First, search for information about this URL or its domain using the search_url_info tool.

Then provide a detailed analysis including:
1. Information about the domain's reputation and ownership
2. Any security concerns or warnings associated with this URL
3. The purpose or content of the website
4. Whether users should be cautious about visiting this site

If the search doesn't return useful information, analyze the URL structure itself for potential security issues.

At the end of your analysis, you MUST provide a clear, definitive conclusion stating whether the URL is malicious or safe.
End with "FINAL CONCLUSION: This URL is [MALICIOUS/SAFE]" - do not express uncertainty or provide conditional statements.
"""
        
        try:
            result = agent_executor.invoke({"input": query})
            analysis = result["output"].strip()
            
            # Return the full analysis
            return "analysis", 1.0, analysis
                
        except Exception as e:
            return "error", 0, f"Error during analysis: {str(e)}"
    
    # Rename the demo method to reflect analysis rather than classification
    def _demo_analyze(self, url):
        """Provide demo analysis when API key is not available"""
        import re
        
        # Create a more detailed analysis output
        analysis = "URL Analysis (Demo Mode):\n\n"
        
        # Extract domain parts for analysis
        try:
            if '//' in url:
                domain = url.split('//')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
                
            domain_parts = domain.split('.')
            tld = domain_parts[-1] if len(domain_parts) > 1 else ""
        except:
            domain = url
            domain_parts = []
            tld = ""
        
        analysis += f"URL: {url}\n"
        analysis += f"Domain: {domain}\n"
        
        # Check domain reputation
        reputable_domains = ['google.', 'microsoft.', 'apple.', 'amazon.', 'github.', 'wikipedia.', 'twitter.', 'linkedin.']
        
        if any(domain.startswith(rep_domain) for rep_domain in reputable_domains):
            analysis += f"\nDomain Reputation: This appears to be a well-known and established domain. "
            analysis += f"Web searches indicate this is a legitimate service provided by a major technology company.\n"
        elif '.edu' in domain:
            analysis += f"\nDomain Reputation: This appears to be an educational institution website. "
            analysis += f"Web searches indicate .edu domains are restricted to accredited educational institutions.\n"
        elif '.gov' in domain:
            analysis += f"\nDomain Reputation: This appears to be a government website. "
            analysis += f"Web searches indicate .gov domains are restricted to official government entities.\n"
        else:
            analysis += f"\nDomain Information: Limited information available in demo mode. "
            analysis += f"With API access, we would perform a real web search to gather more details about this domain.\n"
        
        # Security concerns
        security_concerns = []
        
        # Check for IP address URLs
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            security_concerns.append("The URL uses an IP address instead of a domain name, which is unusual for legitimate websites and often associated with phishing attempts.")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.buzz']
        if any(tld.lower() == s_tld.replace('.', '') for s_tld in suspicious_tlds):
            security_concerns.append(f"The URL uses the TLD '.{tld}' which is sometimes associated with low-cost domains that may be used for malicious purposes.")
        
        # Check for suspicious keywords
        suspicious_keywords = ['login', 'password', 'bank', 'account', 'verify', 'wallet', 'crypto', 'confirm']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            security_concerns.append("The URL contains terms often found in phishing sites that attempt to collect sensitive information.")
        
        # Check for typosquatting
        well_known_domains = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal']
        for known_domain in well_known_domains:
            if known_domain in ''.join(domain_parts) and not any(domain.startswith(d) for d in reputable_domains):
                security_concerns.append(f"The URL contains '{known_domain}' but does not appear to be the official domain, which could indicate typosquatting.")
        
        # Check for unusual country-specific TLDs with well-known brands
        if any(rep_domain.strip('.') in ''.join(domain_parts) for rep_domain in reputable_domains) and tld not in ['com', 'org', 'net', 'edu', 'gov']:
            security_concerns.append(f"This URL uses a country-specific TLD (.{tld}) with what appears to be a well-known brand, which could be suspicious.")
        
        if security_concerns:
            analysis += "\nPotential Security Concerns:\n"
            for i, concern in enumerate(security_concerns, 1):
                analysis += f"{i}. {concern}\n"
        else:
            analysis += "\nNo immediate security concerns detected in the basic analysis.\n"
        
        # Overall assessment
        analysis += "\nRecommendation: "
        if security_concerns:
            analysis += "Exercise caution with this URL. "
            analysis += "Consider verifying the website through official channels before providing any personal information or downloading content."
        else:
            analysis += "The URL appears to be generally safe based on basic analysis. "
            analysis += "However, always practice safe browsing habits and be vigilant when sharing personal information online."
        
        analysis += "\n\nNote: This is a demo analysis. With API access, we would perform a real web search to provide more accurate and detailed information."
        
        return "analysis", 1.0, analysis

class GeminiFewShot:    
    def __init__(self):
        self.api_key = os.environ.get('GEMINI_API_KEY')
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "models/gen-lang-client-0424570342-87f29e2566a1.json"
        
    def classify_url(self, url):
        """
        Analyzes a URL using Google's Gemini API with improved handling.
        Returns detailed security analysis of the URL.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        # Initialize Gemini model with appropriate configuration
        gemini_llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            temperature=0,
            convert_system_message_to_human=True  # Gemini models work better with this flag
        )
        
        # Using a direct approach with Gemini rather than the agent framework
        # Gemini has better structured output with this approach
        system_message = """You are a cybersecurity expert specialized in URL analysis and threat detection.
Your job is to analyze URLs for potential security threats and provide detailed analysis."""

        user_message = f"""Analyze this URL: {url}

Previous examples of URL classifications:
{few_shot_prompt}

Please provide:
1. A detailed analysis of the domain structure, TLD, and overall URL characteristics
2. Any security concerns or red flags
3. A definitive conclusion about whether this URL is safe or malicious

Follow this exact response format:
---
## URL Analysis
[Your detailed analysis here]

## Security Assessment
[List potential security concerns]

## CONCLUSION
This URL is [MALICIOUS/SAFE] - choose one definitively

## Classification
[0 or 1] (where 0 = malicious, 1 = safe)
---

Important: Be especially cautious of:
- Domain spoofing (like youtube.in instead of youtube.com)
- Country-specific TLDs (.in, .ru, etc.) attached to well-known brands
- IP addresses in URLs, excessive subdomains, or suspicious keywords
- Typosquatting and URL obfuscation techniques"""

        try:
            # Call the model directly rather than through agent framework
            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message}
            ]
            
            response = gemini_llm.invoke(messages).content
            
            # Extract classification and conclusion
            classification_match = re.search(r"## Classification\s*\n\s*(\d)", response, re.IGNORECASE)
            conclusion_match = re.search(r"## CONCLUSION\s*\n\s*This URL is (MALICIOUS|SAFE)", response, re.IGNORECASE)
            
            if classification_match:
                output = int(classification_match.group(1))
                
                if output == 1:
                    return "safe", 0.88, response
                elif output == 0:
                    return "malicious", 0.93, response
                else:
                    return "uncertain", 0.5, response
            elif conclusion_match:
                conclusion = conclusion_match.group(1).upper()
                if conclusion == "SAFE":
                    return "safe", 0.85, response
                else:
                    return "malicious", 0.9, response
            else:
                # Additional fallback logic
                if "SAFE" in response.upper() and "MALICIOUS" not in response.upper():
                    return "safe", 0.75, response
                elif "MALICIOUS" in response.upper():
                    return "malicious", 0.8, response
                else:
                    return "uncertain", 0.5, response
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
            
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        # Create a different set of heuristics from the other models
        suspicious_keywords = ['verify', 'account', 'login', 'bank', 'secure', 'update', 'confirm', 'wallet']
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.buzz']
        
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
        Classifies a URL using Llama model with improved formatting.
        Returns analysis of whether a URL is safe or malicious.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
        
        try:    
            # Initialize Groq endpoint for Llama model
            llama_llm = ChatGroq(
                temperature=0, 
                groq_api_key=self.api_key, 
                model_name="llama-3.1-8b-instant"  # Use a model that's more reliable with structured outputs
            )
            
            # For Llama, we'll avoid the complex agent format and use a direct approach
            # with a very structured prompt that's less likely to have formatting issues
            
            prompt = f"""You are a cybersecurity expert. I need you to analyze this URL: {url}

Please provide a detailed analysis that includes:
1. An assessment of the domain structure, TLD, and any suspicious patterns
2. Whether the URL appears to be legitimate or potentially malicious
3. Any security concerns that users should be aware of

Examples of previously classified URLs:
{few_shot_prompt}

Important guidelines:
- Be wary of domain spoofing like 'facebook-login.com' or 'youtube.suspicious-domain.com'
- Country-specific TLDs (like .in, .ru, .cn) with well-known brands should be treated suspiciously
- Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords

Structure your response in this exact format:
1. URL Analysis: [your detailed analysis]
2. Security Concerns: [list any security concerns]
3. CONCLUSION: This URL is [MALICIOUS/SAFE] (choose one definitively)
4. Classification: [0 or 1] (where 0 is malicious and 1 is safe)

Ensure you provide a clear, unambiguous conclusion.
"""
            
            # Direct call without agent framework to avoid format issues
            response = llama_llm.invoke(prompt).content
            
            # Extract classification (last number in the response)
            classification_match = re.search(r"Classification:\s*(\d)", response)
            if classification_match:
                output = classification_match.group(1)
                
                # Extract conclusion section if possible
                conclusion_match = re.search(r"CONCLUSION:.*?(?=\n|$)", response)
                explanation = response
                if conclusion_match:
                    conclusion = conclusion_match.group(0)
                    # Include the conclusion prominently
                    explanation = f"{response}\n\n{conclusion}"
                
                if "1" in output:
                    return "safe", 0.89, explanation
                elif "0" in output:
                    return "malicious", 0.91, explanation
                else:
                    return "uncertain", 0.5, explanation
            else:
                # Fallback extraction
                if "SAFE" in response.upper():
                    return "safe", 0.85, response
                elif "MALICIOUS" in response.upper():
                    return "malicious", 0.87, response
                else:
                    return "uncertain", 0.5, response
                
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

# Add GroqFewShot class
class GroqFewShot:
    def __init__(self):
        self.api_key = os.environ.get('GROQ_API_KEY')
        
    def classify_url(self, url):
        """
        Analyzes a URL using Groq AI with structured prompting.
        Returns detailed security analysis of the URL.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
            
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        # Initialize Groq client
        groq_client = Groq(api_key=self.api_key)
        
        system_message = """You are a cybersecurity expert who specializes in URL and domain safety analysis. 
Your task is to analyze URLs to determine if they are legitimate or malicious.
Provide clear, detailed analysis and be definitive in your classification."""
        
        # Structure the prompt for reliability
        user_message = f"""Analyze this URL carefully and determine if it's legitimate or malicious:

URL: {url}

Previous URL classification examples:
{few_shot_prompt}

Provide your analysis with the following structure:
---
## Domain Analysis
[Analyze the domain structure, TLD, and any suspicious patterns]

## Security Assessment
[List potential security issues or reasons for legitimacy]

## CONCLUSION
This URL is [MALICIOUS/SAFE] - choose one definitively

## Classification
[0 or 1] (where 0 = malicious, 1 = safe)
---

Important guidelines:
1. Be vigilant about domain spoofing (e.g., 'facebook-login.com' instead of 'facebook.com')
2. Consider country-specific TLDs (.in, .ru, .cn) with well-known brands as suspicious unless the brand operates in that country
3. Check for phishing indicators like IP addresses in URLs, excessive subdomains, or suspicious keywords
4. Be definitive in your conclusion - choose either MALICIOUS or SAFE
"""

        try:
            # Use Groq chat completion with structured system and user messages
            response = groq_client.chat.completions.create(
                model="llama3-70b-8192",  # Or another Groq model
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                temperature=0
            )
            
            response_text = response.choices[0].message.content
            
            # Extract classification and conclusion
            classification_match = re.search(r"## Classification\s*\n\s*(\d)", response_text, re.IGNORECASE)
            conclusion_match = re.search(r"## CONCLUSION\s*\n\s*This URL is (MALICIOUS|SAFE)", response_text, re.IGNORECASE)
            
            if classification_match:
                output = int(classification_match.group(1))
                
                if output == 1:
                    return "safe", 0.95, response_text
                elif output == 0:
                    return "malicious", 0.95, response_text
                else:
                    return "uncertain", 0.5, response_text
            elif conclusion_match:
                conclusion = conclusion_match.group(1).upper()
                if conclusion == "SAFE":
                    return "safe", 0.9, response_text
                else:
                    return "malicious", 0.9, response_text
            else:
                # Additional fallback logic
                if "SAFE" in response_text.upper() and "MALICIOUS" not in response_text.upper():
                    return "safe", 0.8, response_text
                elif "MALICIOUS" in response_text.upper():
                    return "malicious", 0.85, response_text
                else:
                    return "uncertain", 0.5, response_text
                
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

class ClaudeFewShot:
    def __init__(self):
        self.api_key = os.environ.get('ANTHROPIC_API_KEY')
        
    def classify_url(self, url):
        """
        Analyzes a URL using Claude with improved structured output.
        Returns detailed security analysis of the URL.
        """
        if not url or not isinstance(url, str) or len(url.strip()) == 0:
            return "error", 0, "Invalid URL provided"
        
        # If no API key is provided, run in demo mode with simulated results
        if not self.api_key:
            return self._demo_classify(url)
            
        # Initialize Claude model
        claude_llm = ChatAnthropic(
            anthropic_api_key=self.api_key,
            model="claude-3-sonnet-20240229",
            temperature=0
        )
        
        # Use direct approach with structured prompt for Claude
        prompt = f"""You are a cybersecurity expert. Analyze this URL carefully and determine if it's legitimate or malicious.

URL to analyze: {url}

Previous URL classification examples:
{few_shot_prompt}

Please provide your analysis in the following structured format:
---
## Domain Analysis
[Analyze the domain structure, TLD, and any suspicious patterns]

## Security Concerns
[List potential security issues, if any]

## Recommendation
[Provide your recommendation about visiting this site]

## CONCLUSION
This URL is [MALICIOUS/SAFE] - choose one definitively

## Classification
[0 or 1] (where 0 = malicious, 1 = safe)
---

Important guidelines:
1. Be especially vigilant about domain spoofing (like 'facebook-login.com' or 'youtube.in')
2. Country-specific TLDs (.in, .ru, .cn) with well-known brands should be treated suspiciously
3. Check for phishing indicators like IP addresses, excessive subdomains, or suspicious keywords
4. Provide a clear, definitive conclusion without uncertainty
"""
        
        try:
            # Direct model invocation
            response = claude_llm.invoke(prompt).content
            
            # Extract classification and conclusion
            classification_match = re.search(r"## Classification\s*\n\s*(\d)", response, re.IGNORECASE)
            conclusion_match = re.search(r"## CONCLUSION\s*\n\s*This URL is (MALICIOUS|SAFE)", response, re.IGNORECASE)
            
            if classification_match:
                output = int(classification_match.group(1))
                
                if output == 1:
                    return "safe", 0.90, response
                elif output == 0:
                    return "malicious", 0.95, response
                else:
                    return "uncertain", 0.5, response
            elif conclusion_match:
                conclusion = conclusion_match.group(1).upper()
                if conclusion == "SAFE":
                    return "safe", 0.88, response
                else:
                    return "malicious", 0.92, response
            else:
                # Additional fallback logic
                if "SAFE" in response.upper() and "MALICIOUS" not in response.upper():
                    return "safe", 0.80, response
                elif "MALICIOUS" in response.upper():
                    return "malicious", 0.85, response
                else:
                    return "uncertain", 0.5, response
                
        except Exception as e:
            return "uncertain", 0.5, f"Error during classification: {str(e)}"
            
    def _demo_classify(self, url):
        """Provide demo classification when API key is not available"""
        # Create a set of heuristics for Claude model
        suspicious_keywords = ['verify', 'secure', 'login', 'account', 'bank', 'wallet', 'password', 'update', 'confirm']
        suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.tk', '.ml', '.work', '.click', '.pw']
        
        # Check for IP address URLs
        import re
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            return "malicious", 0.95, f"Demo Mode (Claude): This URL contains an IP address instead of a domain name, which is a strong indicator of potential phishing. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious TLDs
        if any(tld in url.lower() for tld in suspicious_tlds):
            return "malicious", 0.90, f"Demo Mode (Claude): This URL uses a TLD that is frequently associated with malicious sites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for suspicious keywords in URL
        if sum(url.lower().count(keyword) for keyword in suspicious_keywords) >= 2:
            return "malicious", 0.92, f"Demo Mode (Claude): This URL contains multiple terms commonly associated with phishing attempts. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for extremely long URLs (potential obfuscation)
        if len(url) > 100:
            return "malicious", 0.85, f"Demo Mode (Claude): This URL is unusually long, which can be a sign of obfuscation techniques used in malicious URLs. Without API keys, we're using basic heuristics to classify URLs."
        
        # Check for reputable domains
        reputable_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'youtube.com']
        if any(domain in url.lower() for domain in reputable_domains):
            return "safe", 0.95, f"Demo Mode (Claude): This URL appears to be from a well-established and reputable domain. Without API keys, we're using basic heuristics to classify URLs."
        
        # Educational or government domains
        if '.edu' in url.lower() or '.gov' in url.lower():
            return "safe", 0.93, f"Demo Mode (Claude): This URL belongs to an educational or government domain, which have strict registration requirements and are generally trustworthy. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default behavior for simple URLs
        if len(url) < 35 and url.count('.') <= 2 and url.count('/') <= 3:
            return "safe", 0.80, f"Demo Mode (Claude): This URL has a simple structure characteristic of legitimate websites. Without API keys, we're using basic heuristics to classify URLs."
        
        # Default to uncertain
        return "uncertain", 0.5, f"API key not configured. Running in demo mode with limited functionality. This is a placeholder response from Claude model."