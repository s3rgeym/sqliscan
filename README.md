# SQLiScan  

**SQLiScan** is a command-line tool for detecting SQL injection vulnerabilities in web applications. It processes a list of URLs, sends crafted requests, and analyzes responses to identify potential security risks.  

## Features  
- **Automated SQL injection detection** across multiple URLs  
- **Concurrency control** for efficient scanning  
- **Customizable request parameters** (proxy, user-agent, timeouts, etc.)  
- **Logging support** with different verbosity levels  
- **Configurable depth and retry logic** for thorough testing  

## Usage  

### Basic Scan  
```sh
sqliscan -i urls.txt -o results.json -log debug
```  
Scans URLs from `urls.txt` and saves the results to `results.json`.  

### Advanced Options  
```sh
sqliscan -i urls.txt -o results.json -c 50 -depth 5 -proxy http://127.0.0.1:8080 -ua "CustomAgent/1.0"
```  
- `-c 50` → Sets concurrency to 50 requests  
- `-depth 5` → Crawls up to 5 link levels deep  
- `-proxy` → Routes requests through the specified proxy  
- `-ua` → Uses a custom User-Agent  

### Help  
```sh
sqliscan -h
```  
Displays all available options.  
