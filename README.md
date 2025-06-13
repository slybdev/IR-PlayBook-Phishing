
# 🐟 Incident Response Playbook: Phishing Attack

## 📌 Overview

This playbook outlines the steps for investigating and responding to a phishing email attack. These attacks often aim to harvest credentials or deliver malware through malicious links or attachments.

---

## 📁 Incident Type

- Email-based phishing
- Credential harvesting
- Payload delivery (.docm, .lnk)

---

## 🧠 MITRE ATT&CK Mapping

| Tactic              | Technique                                  |
|---------------------|---------------------------------------------|
| Initial Access      | T1566.001 - Spearphishing Attachment        |
| Initial Access      | T1566.002 - Spearphishing Link              |
| Execution           | T1204.002 - User Execution (Malicious File)|
| Credential Access   | T1556.001 - Phishing for Credentials        |

---

## 🧰 Tools Used

- SIEM (Splunk, ELK)
- VirusTotal
- Email Header Analyzer (MXToolbox, Google Admin Toolbox)
- TheHive
- Shuffle (SOAR)
- Sysmon
- ExifTool or emldump for attachments

---

## 🔍 Detection

### Splunk Query (suspicious attachment)

```spl
index=email subject="*" AND attachment="*.docm" OR url="*.bit.ly*" OR url="*.we.tl*"
````

### Header Clues to Look For:

* SPF/DKIM/DMARC failures
* `Reply-To` mismatch
* Suspicious sending infrastructure
* Unusual Return-Path
* Obfuscated URLs

---

## 🧪 Enrichment (SOAR Python Script Example)

```python
import requests

url = input(url)

headers = {
    "x-apikey": "<Your_virus_total_api_key>"
}

data = {"url": url}
resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
url_id = resp.json()["data"]["id"]

lookup = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
output = lookup.json()

```


You can return fields like:

* `malicious_votes`
* `categories`
* `threat_names`

---

## 🛡️ Containment

* Quarantine affected inbox
* Search environment for similar emails using YARA or mail API
* Block sender IP/domain in email gateway
* Force reset of compromised user credentials
* Identify endpoints that clicked or opened malicious links

---

## 🧼 Eradication

* Remove persistence (e.g., Office macro scripts, Startup folder .lnk files)
* Delete payloads or scripts
* Review GPO and Outlook rules for abuse
* Run antivirus scans

---

## 🧯 Recovery

* Educate the impacted user
* Re-enable MFA if disabled
* Ensure antivirus is updated and active
* Patch all endpoints

---

## 📊 Post-Incident Activities

* Document in TheHive with full case timeline
* Share IOCs with threat intelligence platforms
* Update SIEM rules or detection pipelines
* Conduct tabletop review

---


## 🔗 Related Resources

* [MITRE ATT\&CK: Phishing](https://attack.mitre.org/techniques/T1566/)
* [VirusTotal](https://www.virustotal.com/)
* [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)


