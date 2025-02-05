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

```sh
sqliscan -i urls.txt -o sqli.json -log debug -skip-verify
```   

- `-i` specifies the input file containing URLs to scan
- `-o` sets the output file for scan results
- `-log debug` enables detailed logging
- `-skip-verify` skips SSL certificate verification

All flags:

```sh
sqliscan -h
```
