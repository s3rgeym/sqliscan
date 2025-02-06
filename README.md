# 🚀 SQLiScan  
**SQLiScan** is a powerful command-line tool designed to detect SQL injection vulnerabilities in web applications. It performs **crawling** to extract links and forms from target URLs, systematically testing each endpoint for potential SQL injection vulnerabilities. Whether you're a security researcher or a developer, SQLiScan helps you stay one step ahead of attackers by automating the detection process. 🔒  

---
### ⚠️ **Important Legal Notice**  
This software is intended **solely for ethical purposes**, such as identifying and fixing security vulnerabilities in systems you own or have explicit permission to test.  
- **Prohibited Use**: This tool must not be used for unauthorized access, malicious activities, or any actions that violate laws or terms of service.  
- **User Responsibility**: The user assumes full responsibility for any actions taken using this software.  
- **Compliance**: Ensure compliance with all applicable laws, regulations, and ethical guidelines when using this tool.  

By downloading or using SQLiScan, you agree to these terms and acknowledge that the authors are not liable for any misuse or damages caused by this software.

---

## 🌟 Features  
- **Automated SQL Injection Detection** 🤖: Scans multiple URLs to identify potential SQL injection vulnerabilities.  
- **Crawling and Link Extraction** 🕸️: Crawls target websites to discover links and forms, ensuring comprehensive coverage of all endpoints.  
- **Form Analysis** 📝: Extracts and analyzes HTML forms to test input fields for SQL injection vulnerabilities.  
- **Concurrency Control** ⚡: Efficiently handles multiple requests simultaneously for faster scanning.  
- **Customizable Request Parameters** 🛠️: Supports proxy settings, custom user-agents, timeouts, and more for tailored scans.  
- **Logging Support** 📋: Offers different verbosity levels (`info`, `debug`, etc.) to suit your needs.  
- **Configurable Depth and Retry Logic** 🔍: Ensures thorough testing with adjustable scan depth and retry options.  
- **Cloudflare Challenge Bypass** 🌥️: Handles applications protected by Cloudflare's firewall for uninterrupted scanning.  

---
## 🛠️ Usage  
Get started with SQLiScan by running the following command:  
```sh
sqliscan -i urls.txt -o sqli.json -log debug -skip-verify
```  

### Command Breakdown:  
- `-i`: Specifies the input file containing URLs to scan 📂  
- `-o`: Sets the output file for scan results 📋  
- `-log debug`: Enables detailed logging for advanced insights 🧐  
- `-skip-verify`: Skips SSL certificate verification (useful for self-signed certificates) 🔓  

To view all available flags and their descriptions, run:  
```sh
sqliscan -h
```

---
## 📥 Download  
You can download executables for 🪟 Windows, 🐧 Linux, and 🍎 macOS from [📦 Releases](../../releases).  
