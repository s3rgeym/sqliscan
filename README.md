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

### Output Example:

```json
{"method":"GET","url":"https://site.ru/novostroiky","params":{"flt[all_sq][0]":"","flt[all_sq][1]":"","flt[city]":"2","flt[floor][0]":"","flt[floor][1]":"","flt[floors][0]":"","flt[floors][1]":"","flt[keywords]":"","flt[new_flat]":"1","flt[obj_type]":"flat","flt[price][0]":"","flt[price][1]":"","flt[price_type]":"all","flt[res_cnt]":"1","flt[roomcount][]":"2","flt[sroks][0]":"","flt[sroks][1]":"","show_map":"0","view":"flat"},"error_message":"\u003cb\u003eFatal error\u003c/b\u003e:","title":"","status_code":200,"vuln_param":"flt[keywords]","result_at":"2025-04-03 10:00:00.123456789 +0000 UTC"}
```

---

## 📥 Download

You can download executables for 🪟 Windows, 🐧 Linux, and 🍎 macOS from [📦 Releases](../../releases).
