# Cyber-Projects
This repository showcases Python tools for system security: a File Integrity Checker to detect unauthorized changes, a Vulnerability Scanner for identifying risks, a Penetration Testing Tool for ethical hacking, and an Encryption Tool for securing files with AES-256.

### 1. File Integrity Checker
- Monitors files for unauthorized changes.
- Uses cryptographic hash functions like SHA-256 to detect file tampering.
- Provides detailed logs of file changes.

### 2. Vulnerability Scanner
- Scans systems, networks, and web applications for known vulnerabilities.
- Specifically checks for:
  - Cross-Site Scripting (XSS) vulnerabilities.
  - SQL Injection vulnerabilities in websites.
- Integrates with vulnerability databases to provide up-to-date results.
- Offers detailed vulnerability reports and remediation suggestions.

### 3. Pentesting Toolkit
- Includes essential tools for penetration testing:
  - Port scanning
  - Network traffic analysis
  - Exploit testing
- Easy-to-use command-line interface for automation.

### 4. Encryption Tool
- Features a user-friendly graphical user interface (GUI).
- Encrypts and decrypts files using AES-256 encryption.
- Supports secure key management.
- Ensures data confidentiality and integrity.

## Installation

### Prerequisites
- Python 3.8 or higher
- Required Python libraries (see [requirements.txt](./requirements.txt))

### Steps
1. Clone this repository:
   ```bash
   git clone https://github.com/maheshtodase03/Cyber-Projects.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Cyber-Projects
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### File Integrity Checker
Run the following command to check file integrity:
```bash
python integrity_checker.py --path <directory_path>
```

### Vulnerability Scanner
Scan a website for vulnerabilities:
```bash
python vulnerability_scanner.py --target <target_address>
```

### Pentesting Toolkit
Perform a port scan:
```bash
python pentest_toolkit.py --mode portscan --target <target_address>
```

### Encryption Tool
Run the encryption tool's GUI:
```bash
python encryption_tool.py
```
From the GUI, you can:
- Encrypt a file by selecting it and providing an encryption key.
- Decrypt a file by selecting it and providing the correct decryption key.

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork this repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add some feature"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more information.

## Contact

- **Author**: [Mahesh Todase](https://github.com/MaheshTodase03)
- **GitHub Repository**: [https://github.com/maheshtodase03/Cyber-Projects](https://github.com/maheshtodase03/Cyber-Projects)

## Acknowledgments

- Inspiration and guidance from the cybersecurity community.
- Open-source libraries and tools that made this project possible.
