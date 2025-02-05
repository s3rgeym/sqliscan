# 🚀 SQLiScan  
**SQLiScan** is a powerful command-line tool designed to detect SQL injection vulnerabilities in web applications. It processes a list of URLs, sends crafted requests, and analyzes responses to identify potential security risks. Whether you're a security researcher or a developer, SQLiScan helps you stay one step ahead of attackers. 🔒  

---

## 🌟 Features  
- **Automated SQL Injection Detection** 🤖: Scans multiple URLs to identify potential SQL injection vulnerabilities.  
- **Concurrency Control** ⚡: Efficiently handles multiple requests simultaneously for faster scanning.  
- **Customizable Request Parameters** 🛠️: Supports proxy settings, custom user-agents, timeouts, and more for tailored scans.  
- **Logging Support** 📝: Offers different verbosity levels (`info`, `debug`, etc.) to suit your needs.  
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
