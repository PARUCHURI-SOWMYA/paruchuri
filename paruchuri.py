import streamlit as st
import os
import re
from bandit.api import main as bandit_main
import subprocess
import requests

# Title of the app
st.title("🛡️ Application Security Testing Tool")
st.write("Scan your applications for vulnerabilities and security issues.")

# File upload section
st.sidebar.header("Upload Your Files")
uploaded_file = st.sidebar.file_uploader("Upload a source code file (.py, .js, etc.)", type=["py", "js", "html"])

# URL scanning section
st.sidebar.header("Scan a URL")
url_to_scan = st.sidebar.text_input("Enter a URL to scan for security issues")

# Results Section
st.header("Results")

# File scanning function
def scan_file(file_path):
    """Scan the uploaded file for vulnerabilities using Bandit."""
    st.write(f"Scanning file: `{file_path}`...")
    result = subprocess.run(
        ["bandit", "-r", file_path],
        capture_output=True,
        text=True
    )
    return result.stdout

# URL scanning function
def scan_url(url):
    """Check the URL for potential risks using VirusTotal API."""
    API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Add your VirusTotal API key here
    endpoint = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": API_KEY}
    response = requests.post(endpoint, headers=headers, data={"url": url})
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return {"error": "Unable to scan URL. Check your API key or URL."}

# File scanning
if uploaded_file:
    with open(uploaded_file.name, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(f"File `{uploaded_file.name}` uploaded successfully!")
    st.code(scan_file(uploaded_file.name))

# URL scanning
if url_to_scan:
    st.write(f"Scanning URL: `{url_to_scan}`...")
    result = scan_url(url_to_scan)
    if "error" in result:
        st.error(result["error"])
    else:
        st.success("URL scanned successfully!")
        st.json(result)

# Security best practices
st.header("📋 Security Best Practices")
st.write(
    """
    - **Sanitize Inputs**: Always validate and sanitize user inputs to prevent SQL Injection and XSS attacks.
    - **Use HTTPS**: Ensure all web traffic is encrypted using HTTPS.
    - **Update Dependencies**: Regularly update libraries and dependencies to patch known vulnerabilities.
    - **Secure APIs**: Use proper authentication and authorization mechanisms for APIs.
    """
)
