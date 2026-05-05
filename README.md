# APKdevastate

![Repo Size](https://img.shields.io/github/repo-size/rafosw/APKdevastate)
![Stars](https://img.shields.io/github/stars/rafosw/APKdevastate?style=social)
![Forks](https://img.shields.io/github/forks/rafosw/APKdevastate?style=social)
![Issues](https://img.shields.io/github/issues/rafosw/APKdevastate)


<p align="center">
  <img src="https://github.com/rafosw/APKdevastate/blob/master/ss/fireandroid.gif?raw=true" alt="APKdevastate Banner" width="200"/>
</p>

**APKdevastate** is a powerful Windows application designed to analyze Android APK files for security risks, malware signatures, and suspicious behaviors. The tool helps identify potentially malicious applications by examining permissions, certificate information, and known Remote Access Trojan (RAT) signatures.

The application may be detected as infected by Anti-Virus because it contains RAT names

**CLI Version for Linux**: [https://github.com/rafosw/APKdevastate-cli](https://github.com/rafosw/APKdevastate-cli)



---

# Sample view of the software

## Payload Alert
<img src="https://github.com/rafosw/APKdevastate/blob/master/ss/Screenshot_2.png" width="600" height="350" />

## Malicious Alert
<img src="https://github.com/rafosw/APKdevastate/blob/master/ss/Screenshot_4.png" width="600" height="350" />

## Clean APK
<img src="https://github.com/rafosw/APKdevastate/blob/master/ss/Screenshot_3.png" width="600" height="350" />


## Features

- **Permission Analysis**: Lists and evaluates dangerous Android permissions
- **Certificate Verification**: Validates APK signing certificates against trusted organizations
- **RAT Detection**: Scans for known Remote Access Trojan signatures
- **Hash Generation**: Calculates MD5, SHA1, and SHA256 hashes for file verification
- **Encryption Detection**: Identifies potentially obfuscated or encrypted code
- **Risk Assessment**: Provides an overall security evaluation of the analyzed APK
- **Native Library Scan**: Detects suspicious `.so` libraries
- **Dynamic Loader Check**: Identifies reflection and dynamic class loading
  
---

## Requirements

- .NET Framework 4.5+(downloads automatically)
- Java Runtime Environment

---
## Usage

1. Open the application  
2. Click **"Analyze!"** to choose apk file
3. Click **"RUN"** to begin the security scan
4. Review the detailed analysis results

Example Usage-

[Click here to Watch Demo Video](https://youtu.be/adsLWXGpstg?si=tcqQnxOfy9AtXuMz)

## 🌟 Support the Project

**Love APKdevastate?** Give us a ⭐ on GitHub!


## Installation

Please download the .rar file with the name of the application and then extract it from the .rar to a folder, remember that if the files inside the .rar file are not in a directory, the application will not work

Download latest version:

```bash
https://github.com/rafosw/APKdevastate/releases/tag/APKdevastatev1.6
```

[Read More.](https://rafosw.github.io/posts/apkdevastaten)


> **Disclaimer**: APKdevastate does not guarantee 100% accuracy in all detections or results. Use at your own discretion.
