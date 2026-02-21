import logging
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# OWASP Mapping Constants
OWASP_MAP = {
    "XSS": "https://owasp.org/www-community/attacks/xss/",
    "Reflected XSS": "https://owasp.org/www-community/attacks/xss/",
    "Stored XSS": "https://owasp.org/www-community/attacks/xss/",
    "DOM-based XSS": "https://owasp.org/www-community/attacks/dom-based-xss/",
    "SQL Injection": "https://owasp.org/www-community/attacks/SQL_Injection",
    "SQLi": "https://owasp.org/www-community/attacks/SQL_Injection",
    "Blind SQLi": "https://owasp.org/www-community/attacks/SQL_Injection",
    "CSRF": "https://owasp.org/www-community/attacks/csrf",
    "IDOR": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    "Open Redirect": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/04-Testing_for_Client-Side_URL_Redirect",
    "Clickjacking": "https://owasp.org/www-community/attacks/Clickjacking",
    "CORS Misconfiguration": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    "Missing Security Header": "https://owasp.org/www-project-secure-headers/",
    "Auth Weakness": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
    "Authentication Weakness": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
    "Session Fixation": "https://owasp.org/www-community/attacks/Session_Fixation",
    "Command Injection": "https://owasp.org/www-community/attacks/Command_Injection",
    "LFI": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    "Local File Inclusion": "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    "Sensitive File": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
}

OWASP_ID_MAP = {
    "XSS": "A03:2021-Injection",
    "Reflected XSS": "A03:2021-Injection",
    "Stored XSS": "A03:2021-Injection",
    "DOM-based XSS": "A03:2021-Injection",
    "SQL Injection": "A03:2021-Injection",
    "SQLi": "A03:2021-Injection",
    "Blind SQLi": "A03:2021-Injection",
    "CSRF": "A01:2021-Broken Access Control",
    "IDOR": "A01:2021-Broken Access Control",
    "Open Redirect": "A01:2021-Broken Access Control",
    "Clickjacking": "A05:2021-Security Misconfiguration",
    "CORS Misconfiguration": "A05:2021-Security Misconfiguration",
    "Missing Security Header": "A05:2021-Security Misconfiguration",
    "Auth Weakness": "A07:2021-Identification and Authentication Failures",
    "Authentication Weakness": "A07:2021-Identification and Authentication Failures",
    "Session Fixation": "A07:2021-Identification and Authentication Failures",
    "Command Injection": "A03:2021-Injection",
    "LFI": "A01:2021-Broken Access Control",
    "Local File Inclusion": "A01:2021-Broken Access Control",
    "Sensitive File": "A05:2021-Security Misconfiguration"
}

def get_owasp_link(vuln_name):
    for key, link in OWASP_MAP.items():
        if key.lower() in vuln_name.lower():
            return link
    return "https://owasp.org/www-project-top-ten/"

def get_owasp_id(vuln_name):
    for key, owasp_id in OWASP_ID_MAP.items():
        if key.lower() in vuln_name.lower():
            return owasp_id
    return "N/A"

class Reporter:
    @staticmethod
    def generate_detailed_report(target, scan_time, duration, threads, authenticated, vulnerabilities):
        """
        Generates a detailed report in the strict JSON format required by the user.
        """
        # Calculate Severity Counts
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        enriched_vulns = []
        for v in vulnerabilities:
            # Normalize Severity
            sev = v.get('severity', 'Info').capitalize()
            if sev not in severity_counts: sev = 'Info'
            severity_counts[sev] += 1
            
            # Enrich fields if missing to match strict requirement
            # Required: name, severity, endpoint, parameter, payload, evidence, action_url, http_method, input_field_name, request, response, owasp_reference, owasp_id
            
            vuln_out = v.copy()
            
            # 1. Basic Fields Defaults
            vuln_out.setdefault('name', 'Unknown Vulnerability')
            vuln_out.setdefault('severity', 'Info')
            vuln_out.setdefault('endpoint', target)
            vuln_out.setdefault('parameter', '')
            vuln_out.setdefault('payload', '')
            vuln_out.setdefault('evidence', '')
            
            # 2. Derived Fields
            if 'action_url' not in vuln_out or not vuln_out['action_url']:
                vuln_out['action_url'] = vuln_out.get('endpoint', target)
                
            if 'input_field_name' not in vuln_out or not vuln_out['input_field_name']:
                vuln_out['input_field_name'] = vuln_out.get('parameter', '')
                
            if 'http_method' not in vuln_out or not vuln_out['http_method']:
                 # Try to extract from request if available
                 req = vuln_out.get('request', '')
                 if req and req.startswith('POST'):
                     vuln_out['http_method'] = 'POST'
                 else:
                     vuln_out['http_method'] = 'GET' 

            # 3. Request/Response Defaults
            vuln_out.setdefault('request', '')
            vuln_out.setdefault('response', '')

            # Keep full response (already truncated in utils.py if needed)
            if vuln_out['response']:
                 pass # Maintain the full response captured for evidence accuracy

            # 4. OWASP Enrichment
            if 'owasp_reference' not in vuln_out or not vuln_out['owasp_reference']:
                vuln_out['owasp_reference'] = get_owasp_link(vuln_out['name'])
                
            if 'owasp_id' not in vuln_out or not vuln_out['owasp_id']:
                vuln_out['owasp_id'] = get_owasp_id(vuln_out['name'])
            
            # 5. PoC URL Construction
            if 'poc_url' not in vuln_out:
                vuln_out['poc_url'] = ''
                
                # Only strictly valid for GET usually, or if the vuln is in the URL path/query
                if vuln_out.get('http_method') == 'GET' and vuln_out.get('parameter') and vuln_out.get('payload'):
                    try:
                        p_url = vuln_out['endpoint']
                        param = vuln_out['parameter']
                        payload = vuln_out['payload']
                        
                        parsed = urlparse(p_url)
                        query_params = parse_qs(parsed.query)
                        
                        # We force the specific param to be the payload
                        query_params[param] = [payload]
                        
                        new_query = urlencode(query_params, doseq=True) 
                        
                        vuln_out['poc_url'] = urlunparse(parsed._replace(query=new_query))
                        
                    except Exception as e:
                         # Fallback
                         sep = "&" if "?" in vuln_out['endpoint'] else "?"
                         vuln_out['poc_url'] = f"{vuln_out['endpoint']}{sep}{vuln_out['parameter']}={vuln_out['payload']}"

            enriched_vulns.append(vuln_out)

        # Risk Score Calculation
        # Formula: Critical*100 + High*50 + Medium*10 + Low*1
        risk_score = (severity_counts["Critical"] * 100) + \
                     (severity_counts["High"] * 50) + \
                     (severity_counts["Medium"] * 10) + \
                     (severity_counts["Low"] * 1)
                     
        # Risk Grade
        if severity_counts["Critical"] > 0: risk_grade = "F"
        elif severity_counts["High"] > 0: risk_grade = "D"
        elif severity_counts["Medium"] > 0: risk_grade = "C"
        elif severity_counts["Low"] > 0: risk_grade = "B"
        else: risk_grade = "A"

        return {
            "scan_metadata": {
                "target": target,
                "scan_time": scan_time,
                "duration_seconds": duration,
                "threads_used": threads,
                "authenticated": authenticated
            },
            "chart_values": {
                "labels": ["Critical", "High", "Medium", "Low", "Info"],
                "data": [
                    severity_counts["Critical"],
                    severity_counts["High"],
                    severity_counts["Medium"],
                    severity_counts["Low"],
                    severity_counts["Info"]
                ]
            },
            "severity_summary": severity_counts,
            "risk_score": risk_score,
            "risk_grade": risk_grade,
            "vulnerabilities": enriched_vulns
        }

    @staticmethod
    def group_vulnerabilities(vulnerabilities):
        """
        Groups vulnerabilities by Name and Severity (Legacy/Condensed View).
        Kept for backward compatibility if needed.
        """
        grouped = {}
        
        for v in vulnerabilities:
            key = (v['name'], v['severity'])
            
            if key not in grouped:
                grouped[key] = {
                    "name": v['name'],
                    "severity": v['severity'],
                    "description": v.get('evidence', 'Vulnerability detected based on behavioral analysis.'),
                    "owasp_id": v.get('owasp_id', 'N/A'),
                    "owasp_reference": v.get('owasp_reference', 'N/A'),
                    "affected_assets": []
                }
            
            asset = {
                "url": v['endpoint'],
                "parameter": v['parameter'],
                "payload": v.get('payload', 'N/A'),
                "request": v.get('request', 'N/A'),
                "response": v.get('response', 'N/A')
            }
            
            if asset not in grouped[key]['affected_assets']:
                grouped[key]['affected_assets'].append(asset)
                
        report_list = []
        for key, data in grouped.items():
            report_list.append(data)
            
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        report_list.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        return report_list


