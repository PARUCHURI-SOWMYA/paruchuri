import streamlit as st
import subprocess
import requests

# Title of the app
st.title("🛡️ Application Security Testing Tool")
st.write("Scan your applications for vulnerabilities and security issues.")

# Sidebar for file upload
st.sidebar.header("Upload Your Files")
uploaded_file = st.sidebar.file_uploader("Upload a source code file (.py, .js, etc.)", type=["py", "js", "html"])

# Sidebar for URL scanning
st.sidebar.header("Scan a URL")
url_to_scan = st.sidebar.text_input("Enter a URL to scan for security issues")

# Results Section
st.header("Results")

# Function to scan Python files using Bandit
def scan_file_with_bandit(file_path):
    """Scan the uploaded file for vulnerabilities using Bandit."""
    try:
        st.write(f"Scanning file: `{file_path}`...")
        result = subprocess.run(
            ["bandit", "-r", file_path],  # Recursive scan using Bandit
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stderr
    except Exception as e:
        return f"Error running Bandit: {str(e)}"

# Function to scan a URL using VirusTotal API
def scan_url(url):
    """Check the URL for potential risks using VirusTotal API."""
    API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your VirusTotal API key
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.post(endpoint, headers=headers, data={"url": url})
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return {"error": f"Failed to scan URL: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error scanning URL: {str(e)}"}

# Handle file scanning
if uploaded_file:
    with open(uploaded_file.name, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success(f"File `{uploaded_file.name}` uploaded successfully!")
    scan_result = scan_file_with_bandit(uploaded_file.name)
    st.text("Scan Results:")
    st.code(scan_result)

# Handle URL scanning
if url_to_scan:
    st.write(f"Scanning URL: `{url_to_scan}`...")
    result = scan_url(url_to_scan)
    if "error" in result:
        st.error(result["error"])
    else:
        st.success("URL scanned successfully!")
        st.json(result)

# Security best practices section
st.header("📋 Security Best Practices")
st.write(
    """
    - **Sanitize Inputs**: Always validate and sanitize user inputs to prevent SQL Injection and XSS attacks.
    - **Use HTTPS**: Ensure all web traffic is encrypted using HTTPS.
    - **Update Dependencies**: Regularly update libraries and dependencies to patch known vulnerabilities.
    - **Secure APIs**: Use proper authentication and authorization mechanisms for APIs.
    """
)
