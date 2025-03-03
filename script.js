// Importing suspicious keywords and TLDs from keywords.js
import { suspiciousKeywords, suspiciousTlds } from './src/js/keywords.js';

const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");
const resultDiv = document.getElementById("result");
const resultMessage = document.getElementById("resultMessage");
const resultIcon = document.getElementById("resultIcon");
const themeToggle = document.getElementById("toggleTheme");
const themeIcon = document.getElementById("themeIcon");
const loadingIndicator = document.getElementById("loadingIndicator");  // Loading indicator element
const historyDiv = document.getElementById("historyDiv"); // Div to display URL history

let isDarkMode = true;
let urlHistory = []; // Array to store the history of checked URLs

// Initialize Dark Mode
document.body.classList.add("dark-mode");

// Hide the loader by default when the page loads
loadingIndicator.style.display = "none";

// Toggle theme between dark and light mode
function toggleTheme() {
    isDarkMode = !isDarkMode;
    document.body.classList.toggle("dark-mode", isDarkMode);
    document.body.classList.toggle("light-mode", !isDarkMode);
    themeIcon.src = isDarkMode ? "moon-icon.svg" : "sun-icon.svg";
}

// Show the result of URL check
function showResult(status, icon, message) {
    resultDiv.style.display = "flex";
    resultDiv.className = `result ${status}`;
    resultIcon.src = icon;
    resultIcon.alt = status === "safe" ? "Safe Icon" : "Danger Icon";
    resultMessage.innerHTML = message;
    loadingIndicator.style.display = "none"; // Hide the loader once result is shown
}

// Updated function to update history with clickable URLs and copy functionality
function updateHistory(url) {
    urlHistory.push(url);
    historyDiv.innerHTML = `
        <h3>Checked URLs History:</h3>
        <ul>
            ${urlHistory.map(url => `
                <li>
                    <span class="history-url" data-url="${url}">${url}</span>
                    <button class="copy-button" data-url="${url}">
                        <img src="copy.svg" alt="Copy" class="copy-icon" />
                    </button>
                </li>`).join('')}
        </ul>
    `;

    // Add event listeners to history URLs for rechecking
    document.querySelectorAll('.history-url').forEach(item => {
        item.addEventListener('click', () => {
            urlInput.value = item.dataset.url;
            checkURL();
        });
    });

    // Add event listeners to copy buttons
    document.querySelectorAll('.copy-button').forEach(button => {
        button.addEventListener('click', (e) => {
            const urlToCopy = e.target.closest('.copy-button').dataset.url;
            navigator.clipboard.writeText(urlToCopy).then(() => {
                // Show success icon after copying
                const successIcon = `<img src="success.svg" alt="Success" class="success-icon" />`;
                button.innerHTML = successIcon;
                setTimeout(() => {
                    button.innerHTML = `<img src="copy.svg" alt="Copy" class="copy-icon" />`;
                }, 1000); // Reset copy icon after 1 second
            }).catch(err => {
                console.error('Failed to copy text: ', err);
            });
        });
    });
}

// Function to check DNS for suspicious patterns
function checkDNS(domain) {
    const dnsWarnings = [];
    
    const suspiciousPatterns = {
        repeatedChars: /(.)\1{2,}/, 
        numberLetterMix: /([0-9][a-z])|([a-z][0-9]){2,}/i,
        nonAsciiChars: /[\u0080-\uffff]/,
        excessiveSubdomains: /\./g
    };

    if (suspiciousPatterns.repeatedChars.test(domain)) {
        dnsWarnings.push("⚠️ Oops, too many repeating characters. Just like your broken record.");
    }

    if (suspiciousPatterns.numberLetterMix.test(domain)) {
        dnsWarnings.push("⚠️ Is this a secret code? Suspicious number-letter combos detected.");
    }

    if (suspiciousPatterns.nonAsciiChars.test(domain)) {
        dnsWarnings.push("⚠️ Whoa, this domain is speaking in a language I don’t understand. Non-ASCII characters spotted.");
    }

    if ((domain.match(suspiciousPatterns.excessiveSubdomains) || []).length > 3) {
        dnsWarnings.push("⚠️ Did you get lost in subdomain land? Too many subdomains.");
    }

    return dnsWarnings;
}

// Function to check for redirects in the URL
function checkRedirects(url) {
    const redirectIndicators = [
        "redirect", "next", "url=", "forward", "target", "goto", "click"
    ];

    const detectedRedirects = redirectIndicators.filter(indicator =>
        url.toLowerCase().includes(indicator)
    );

    return detectedRedirects.length > 0
        ? [`⚠️ Redirects galore! Found: ${detectedRedirects.join(", ")}. Time to rethink clicking.`]
        : [];
}

async function checkURL() {
    let url = urlInput.value.trim();

    // Convert the protocol (http or https) to lowercase
    if (url.startsWith("http://")) {
        url = "http://" + url.slice(7).toLowerCase();
    } else if (url.startsWith("https://")) {
        url = "https://" + url.slice(8).toLowerCase();
    }

    if (!url) {
        showResult("danger", "error-icon.svg", `
            <p class="error-title">⚠️ Hmm... Something's missing here.</p>
            <ul>
                <li>Did you forget to enter a URL? Go ahead, try again.</li>
            </ul>
        `);
        return;
    }

    try {
        // Show loader before starting the check
        loadingIndicator.style.display = "flex";

        // Check if URL has a protocol (http:// or https://)
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            showResult("danger", "error-icon.svg", `
                <p class="error-title">⚠️ Oh no, no protocol?</p>
                <ul>
                    <li>Please add 'http://' or 'https://' in front of the URL. It's not that hard.</li>
                </ul>
            `);
            return;
        }

        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname;
        const tld = domain.split(".").pop();
        const isHttps = parsedUrl.protocol === "https:";

        let messages = [];
        let allGood = true;

        if (isHttps) {
            messages.push("✅ HTTPS is enabled. Stay secure and classy.");
        } else {
            allGood = false;
            messages.push("⚠️ No HTTPS? Not Secured.");
        }

        const dnsWarnings = checkDNS(domain);
        if (dnsWarnings.length > 0) {
            allGood = false;
            messages.push(...dnsWarnings);
        }

        const redirectWarnings = checkRedirects(url);
        if (redirectWarnings.length > 0) {
            allGood = false;
            messages.push(...redirectWarnings);
        }

        if (suspiciousTlds.includes(`.${tld}`)) {
            allGood = false;
            messages.push(`⚠️ The domain ends with .${tld} — a red flag for scams. Proceed with caution.`);
        } else {
            messages.push(`✅ This domain’s TLD is trustworthy. (.${tld})`);
        }

        const foundKeywords = suspiciousKeywords.filter(keyword => domain.includes(keyword));
        if (foundKeywords.length > 0) {
            allGood = false;
            messages.push(`⚠️ Keywords like "${foundKeywords.join('", "')}"? Sounds fishy.`);
        } else {
            messages.push("✅ No suspicious keywords found. It's like a breath of fresh air.");
        }

        // Add a 1-second delay before showing the result
        setTimeout(() => {
            if (allGood) {
                showResult("safe", "safe-icon.svg", `
                    <p class="safe-title">✅ Congratulations, You Found a Safe Link!</p>
                    <ul>
                        ${messages.map(msg => `<li>${msg}</li>`).join("")}
                    </ul>
                    <p class="safe-recommendation">✅ My recommendation: Go ahead, click it, I guess.</p>
                `);
            } else {
                showResult("danger", "danger-icon.svg", `
                    <p class="error-title">⚠️ Potential Scam, Not So Fast!</p>
                    <ul>
                        ${messages.map(msg => `<li>${msg}</li>`).join("")}
                    </ul>
                    <p class="error-recommendation">⚠️ Avoid this link, This is a scam.</p>
                `);
            }

            // Update history after checking the URL
            updateHistory(url);
        }, 1000);  // 1-second delay
    } catch (e) {
        showResult("danger", "error-icon.svg", `
            <p class="error-title">❌ Invalid URL</p>
            <ul>
                <li>Let’s not be dramatic, just make sure you enter a proper URL next time.</li>
            </ul>
        `);
    } finally {
        // Ensure the loader is visible for 1 second before being hidden
        setTimeout(() => {
            loadingIndicator.style.display = "none";
        }, 1000);  // 1-second delay before hiding the loader
    }
}
urlInput.addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
        checkURL();
    }
});

document.getElementById("pasteButton").addEventListener("click", function() {
    navigator.clipboard.readText().then(text => {
        urlInput.value = text;
        checkURL();
    }).catch(e => {
        console.error("Failed to paste clipboard contents", e);
    });
});

themeToggle.addEventListener("click", toggleTheme);
checkButton.addEventListener("click", checkURL);
