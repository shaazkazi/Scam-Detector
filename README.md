# Scam Detect

Scam Detect is an advanced URL security checker that helps users identify potentially malicious or scam websites before clicking on them. The tool analyzes URLs for multiple risk factors and provides an intuitive safety rating.

## 🔗 Live Demo
[scamdetect.netlify.app](https://scamdetect.netlify.app)

## 🚀 Features
- 🔍 **Real-time URL analysis** - Check any URL for potential security risks
- 🛡️ **Multi-factor detection** - Analyzes domains for multiple risk indicators
- 📊 **Safety ratings** - Get a clear safety score out of 100
- 📱 **Responsive design** - Works on desktop and mobile devices
- 🌓 **Dark/light mode** - Choose your preferred theme
- 📝 **Search history** - Keep track of previously checked URLs
- 📋 **Quick copy** - Easily copy URLs with one click

## 🛠️ Technologies Used
- HTML5 & CSS3
- JavaScript (ES6+)
- Google Safe Browsing API integration
- Netlify for hosting

## 🔍 How It Works
Scam Detect analyzes URLs using multiple security checks:

- **Domain Analysis** - Checks for suspicious TLDs, keywords, and patterns
- **HTTPS Verification** - Ensures secure connections
- **Redirect Detection** - Identifies suspicious redirects
- **Pattern Recognition** - Detects typo-squatting, excessive subdomains, and other phishing techniques
- **Safe Browsing API** - Cross-references with known malicious sites

## ⚙️ Installation and Setup
To run this project locally:

```sh
# Clone the repository
git clone https://github.com/yourusername/scam-detect.git

# Navigate to the project directory
cd scam-detect

# Open the project in your browser
# You can use any local server, for example with Python:
python -m http.server
```

### Set up your own instance with Google Safe Browsing API
1. Obtain a Google Safe Browsing API key
2. Replace the API key in `src/js/detector.js`
3. Update the `CLIENT_ID` in the same file

## 📁 Project Structure
```
scam-detect/
├── index.html                # Main HTML file
├── styles.css                # CSS styles
├── script.js                 # Main JavaScript file
├── src/
│   ├── js/
│   │   ├── detector.js       # URL security analysis
│   │   └── keywords.js       # Suspicious keywords and TLDs
│   └── api/
│       └── urlChecker.js     # API integration
├── manifest.json             # PWA manifest
└── icons/                    # App icons and UI elements
```

## 🖥️ How to Use
1. Enter a URL in the input field (including `http://` or `https://`)
2. Click **"Check URL"** or press **Enter**
3. Review the safety analysis results
4. Check the safety score out of 100
5. Use the history section to revisit previously checked URLs

## 📸 Screenshots
(Include relevant screenshots here)

## 🤝 Contributing
Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📜 License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements
- Built by **Shaaz Kazi**
- Shield icon by **Feather Icons**
- Inspired by the need to make the web safer for everyone

© 2023 Scam Detect. All rights reserved.
