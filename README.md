# SQLiScan  

**SQLiScan** is a command-line tool for detecting SQL injection vulnerabilities in web applications. It processes a list of URLs, sends crafted requests, and analyzes responses to identify potential security risks.  

## Features  
- **Automated SQL injection detection** across multiple URLs  
- **Concurrency control** for efficient scanning  
- **Customizable request parameters** (proxy, user-agent, timeouts, etc.)  
- **Logging support** with different verbosity levels  
- **Configurable depth and retry logic** for thorough testing 
- **Cloudflare bypass** for applications behind the firewall
  
## Usage  

### Basic Scan  
```sh
sqliscan -i urls.txt -o results.json -log debug
```  
Scans URLs from `urls.txt` and saves the results to `results.json`.  

### Help  
```sh
sqliscan -h
```  
Displays all available options.  
