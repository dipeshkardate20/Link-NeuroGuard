from cerebras.cloud.sdk import Cerebras
from urllib.parse import urlparse
from datetime import datetime
import pandas as pd
import Levenshtein
import tldextract
import requests
import json
import math
import re
import os



GOOGLE_API_KEY = "AIzaSyDRFGIrT87ycrIbgNgKG2ZFyDZ7NRugwZo"
client = Cerebras(api_key=os.environ.get("csk-fckkf8whfknjpf94fyx69h4tjw2x6c9fp6cete9txtkp3kpx"),)
CSV_PATH = "top-1m.csv"


print("Loading Top 1M dataset...")
top_domains_df = pd.read_csv(CSV_PATH)


def check_google_blacklist(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "threat-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(api_url, json=payload, timeout=5).json()
        return (True, res['matches'][0]['threatType']) if "matches" in res else (False, "Clean")
    except:
        return (False, "Error")


def get_min_levi_dist(target_url):
    try:
        
        ext = tldextract.extract(target_url)
        
        
        if ext.domain and ext.suffix:
            target_domain = f"{ext.domain}.{ext.suffix}"
        elif ext.domain:
            target_domain = ext.domain 
        else:
            return {"target": "Invalid URL", "closest": "None", "distance": "N/A"}


        lower, upper = max(1, len(target_domain)-3), len(target_domain)+3        
        valid_domains = top_domains_df.dropna(subset=['domain'])
        subset = valid_domains[valid_domains['domain'].astype(str).str.len().between(lower, upper)].copy()
        
        if subset.empty:
            return {
                "target": target_domain,
                "closest": "No similar domains found",
                "distance": 999 
            }
        
        subset['dist'] = subset['domain'].apply(lambda x: Levenshtein.distance(str(x), target_domain))
        best_match = subset.loc[subset['dist'].idxmin()]
        return {
            "target": target_domain,
            "closest": best_match['domain'],
            "distance": int(best_match['dist'])
        }

    except Exception as e:
        print(f"Levenshtein Engine Error: {e}")
        return {
            "target": "Unknown",
            "closest": "Engine Error",
            "distance": 999
        }


def get_redirect_info(url):
    try:
        target = url if '://' in url else 'http://' + url
        response = requests.get(target, timeout=5, allow_redirects=True)
        return {
            "count": len(response.history),
            "final_url": response.url,
            "chain": [r.url for r in response.history] + [response.url]
        }
    except:
        return {"count": 0, "final_url": url, "chain": [url]}


def get_llm_verdict(evidence):
    prompt = f"""
    Analyze this URL security data:
    - URL: {evidence['url']}
    - Google Blacklist: {evidence['blacklist_status']}
    - Closest Legitimate Domain: {evidence['levi']['closest']} (Distance: {evidence['levi']['distance']})
    - Redirect Count: {max(0,evidence['redirects']['count']-1)}

    Any form of URL shortner is considered as not secure,
    
    Provide a verdict (Safe, Suspicious, or Malicious), The Threat type (Benign, Malware, Phishing Link, or Suspicious Link), and a short 1-sentence justification, the user cannot see the evidence.
    """

    stream = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert. Return JSON: {'verdict': '...', 'reasoning': '...', 'Threat type': '...'}"},
            {"role": "user", "content": prompt}
        ],
        model="llama3.1-8b",
        stream=True,
        max_completion_tokens=4096,
        temperature=0.2,
        top_p=1
    )

    ALL=""
    for chunk in stream:
        ALL+=chunk.choices[0].delta.content or ""
    
    return ALL


def get_domain_info(raw_url):
    try:
        
        ext = tldextract.extract(raw_url)
        if ext.domain and ext.suffix:
            domain = f"{ext.domain}.{ext.suffix}"
        else:
            return {"registrar": "Unknown", "creation_date": "Unknown", "age_days": "Unknown"}
        
        rdap_url = f"https://rdap.org/domain/{domain}"
        response = requests.get(rdap_url, timeout=5, allow_redirects=True)
        
        if response.status_code != 200:
            return {"registrar": "Unknown", "creation_date": "Unknown", "age_days": "Unknown"}

        data = response.json()
        
        
        registrar = "Unknown"
        entities = data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    
                    for item in vcard[1]:
                        if item[0] == 'fn':
                            registrar = item[3]
                            break

        
        creation_date = "Unknown"
        age_days = "Unknown"
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate")[:10]
                
                try:
                    date_obj = datetime.strptime(creation_date, "%Y-%m-%d")
                    age_days = (datetime.now() - date_obj).days
                except:
                    pass
                break
        
        return {
            "registrar": registrar,
            "creation_date": creation_date,
            "age_days": age_days
        }

    except Exception as e:
        print(f"RDAP Lookup Error: {e}")
        return {"registrar": "Unknown", "creation_date": "Unknown", "age_days": "Unknown"}



def full_analysis(url):
    is_bad, reason = check_google_blacklist(url)
    
    levi_data = get_min_levi_dist(url)
    domain_info = get_domain_info(url)

    redirect_data={"count": 1, "final_url": url, "chain": [url]}
    if not(is_bad):
        redirect_data = get_redirect_info(url)
    
    
    evidence = {
        "url": url,
        "blacklist_status": reason,
        "levi": levi_data,
        "redirects": redirect_data,
        "domain_info": domain_info
    }
    
    return {**evidence,**json.loads(get_llm_verdict(evidence).split('```')[1][4:])}






def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = text.count(x) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(url):
    url_str = str(url).lower().strip()
    features = {}

    
    features['url_length'] = len(url_str)
    features['count_dot'] = url_str.count('.')
    features['count_hyphen'] = url_str.count('-')
    features['count_at'] = url_str.count('@')
    features['count_double_slash'] = url_str.count('//') - (1 if '://' in url_str else 0)
    features['count_digits'] = sum(c.isdigit() for c in url_str)
    features['count_special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url_str))
    features['is_https'] = 1 if url_str.startswith('https') else 0
    
    suspicious_words = ['login', 'secure', 'account', 'update', 'verify', 'bank']
    features['has_suspicious_words'] = 1 if any(word in url_str for word in suspicious_words) else 0
    features['shannon_entropy'] = calculate_entropy(url_str)
    
    letter_count = sum(c.isalpha() for c in url_str)
    features['digit_to_letter_ratio'] = features['count_digits'] / (letter_count + 1e-5)

    try:
        parsed = urlparse(url_str if '://' in url_str else 'http://' + url_str)
        domain = parsed.netloc.replace('www.', '')
        features['domain_length'] = len(domain)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['has_ip_address'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', domain) else 0
        features['uses_shortener'] = 1 if any(s in domain for s in ['bit.ly', 't.co', 'goo.gl']) else 0
        features['has_suspicious_tld'] = 1 if any(domain.endswith(t) for t in ['.xyz', '.top', '.club']) else 0
        features['count_subdomains'] = domain.count('.')
        vowels = sum(1 for c in domain if c in 'aeiou')
        features['domain_vowel_consonant_ratio'] = vowels / (len(domain) - vowels + 1e-5)
        features['path_to_url_ratio'] = features['path_length'] / (features['url_length'] + 1e-5)
    except:
        for f in ['domain_length', 'path_length', 'query_length', 'has_ip_address', 
                  'uses_shortener', 'has_suspicious_tld', 'count_subdomains', 
                  'domain_vowel_consonant_ratio', 'path_to_url_ratio']:
            features[f] = -1

    return pd.Series(features)
