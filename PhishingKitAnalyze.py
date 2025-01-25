#!/usr/bin/env python3
import sys, os, zipfile, tempfile, re
from pathlib import Path

# Patterns suspects pr scripts
SUSPICIOUS_PATTERNS = {
    "mail(": r"\bmail\s*\(",
    "eval(": r"\beval\s*\(",
    "base64_decode(": r"\bbase64_decode\s*\(",
    "curl": r"\bcurl_?\w*\(",
    "fsockopen": r"\bfsockopen\s*\(",
    "exec(": r"\bexec\s*\(",
    "paswd": r"[Pp]assword",
    "cc": r"(credit.card|cc_number)",
    "smtp": r"[Ss][Mm][Tt][Pp]",
    "config": r"[Cc][Oo][Nn][Ff][Ii][Gg]",
    "obfusc": r"gzinflate|gzdecode|str_rot13"
}

# Mots-clés pr txt/log
TEXT_KEYWORDS = [
    r"password", r"user", r"login", r"admin", r"credential", 
    r"paypal", r"bank", r"account", r"smtp", r"host", r"key"
]

# Regex pr extra info
REGEX_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
REGEX_IP = r"\b\d{1,3}(\.\d{1,3}){3}\b"
REGEX_PHONE = r"\+?\d{1,3}[- .]?\(?\d+\)?[- .]?\d+(?:[- .]?\d+)+"
REGEX_URL = r"(https?://[^\s'\"<>]+)"

def extract_zip(zippath):
    # Ext dans tmp
    if not zipfile.is_zipfile(zippath):
        print(f"[ERR] {zippath} pas ZIP valide.")
        sys.exit(1)
    tmp = tempfile.mkdtemp(prefix="phish_")
    with zipfile.ZipFile(zippath, 'r') as z:
        z.extractall(tmp)
    return tmp

def suspicious_scan(fpath):
    # Check patterns scripts
    found = []
    try:
        with open(fpath, 'r', encoding="utf-8", errors="ignore") as f:
            c = f.read()
            for nm, pat in SUSPICIOUS_PATTERNS.items():
                if re.search(pat, c, flags=re.IGNORECASE):
                    found.append(f"Pattern '{nm}'")
    except:
        pass
    return found

def text_keywords_scan(fpath):
    # Check mots-clés txt/log
    found = []
    try:
        with open(fpath, 'r', encoding="utf-8", errors="ignore") as f:
            c = f.read()
            for kw in TEXT_KEYWORDS:
                if re.search(kw, c, re.IGNORECASE):
                    found.append(f"Motclé '{kw}'")
    except:
        pass
    return found

def advanced_info_scan(fpath):
    # Cherche mails, IP, phone, url
    found = []
    try:
        with open(fpath, 'r', encoding="utf-8", errors="ignore") as f:
            c = f.read()
            mails = re.findall(REGEX_EMAIL, c)
            ips = re.findall(REGEX_IP, c)
            phones = re.findall(REGEX_PHONE, c)
            urls = re.findall(REGEX_URL, c)
            if mails:
                found.append(f"Emails: {', '.join(set(mails))}")
            if ips:
                # ip findall capture un groupe pour (.\d{1,3}) => on normalise
                realips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", c)
                found.append(f"IPs: {', '.join(set(realips))}")
            if phones:
                found.append(f"Phones: {', '.join(set(phones))}")
            if urls:
                found.append(f"URLs: {', '.join(set(urls))}")
    except:
        pass
    return found

def is_text_file(fpath):
    # Check ext + binaire
    ext = fpath.suffix.lower()
    if ext in [".txt", ".log", ".csv", ".conf", ".ini", ".php", ".js", ".html", ".htm", ".asp", ".py", ".sh"]:
        return True
    try:
        with open(fpath, 'rb') as f:
            chunk = f.read(1024)
        np = sum(c < 32 and c not in (9,10,13) for c in chunk)
        if (np/len(chunk)) < 0.3:
            return True
    except:
        pass
    return False

def analyze_kit(zippath, rpt="rapport.txt"):
    # Ext
    ext_dir = extract_zip(zippath)
    all_find = []
    # Parcours
    for rt, d, files in os.walk(ext_dir):
        for fn in files:
            fp = Path(rt)/fn
            subreport = []
            if is_text_file(fp):
                subreport += suspicious_scan(fp)
                subreport += text_keywords_scan(fp)
                subreport += advanced_info_scan(fp)
            if subreport:
                all_find.append((str(fp), subreport))
    # Aff
    if not all_find:
        print("[INFO] RAS.")
    else:
        print("[!!] Suspicious :")
        for p, fnd in all_find:
            print(f"- {p}")
            for detail in fnd:
                print(f"   -> {detail}")
    # Save
    with open(rpt, "w", encoding="utf-8") as f:
        if not all_find:
            f.write("Aucun élément suspect.\n")
        else:
            f.write("Suspicious:\n\n")
            for p, fnd in all_find:
                f.write(f"{p}\n")
                for d in fnd:
                    f.write(f"  -> {d}\n")
                f.write("\n")

def main():
    if len(sys.argv) < 2:
        print("Donne ZIP.")
        sys.exit(1)
    z = sys.argv[1]
    analyze_kit(z)

if __name__ == "__main__":
    main()
