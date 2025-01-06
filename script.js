const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");
const resultDiv = document.getElementById("result");
const resultMessage = document.getElementById("resultMessage");
const resultIcon = document.getElementById("resultIcon");
const themeToggle = document.getElementById("toggleTheme");

const themeIcon = document.getElementById("themeIcon");

let isDarkMode = true;

// Initialize Dark Mode
document.body.classList.add("dark-mode");

// Toggle Theme
function toggleTheme() {
    isDarkMode = !isDarkMode;
    document.body.classList.toggle("dark-mode", isDarkMode);
    document.body.classList.toggle("light-mode", !isDarkMode);
    themeIcon.src = isDarkMode ? "moon-icon.svg" : "sun-icon.svg";
}

themeToggle.addEventListener("click", toggleTheme);

// Show Result Function
function showResult(status, icon, message) {
    resultDiv.style.display = "flex";
    resultDiv.className = `result ${status}`;
    resultIcon.src = icon;
    resultIcon.alt = status === "safe" ? "Safe Icon" : "Danger Icon";
    resultMessage.innerHTML = message;
}

// Check URL Functionality
function checkURL() {
    const url = urlInput.value.trim();

    if (!url) {
        showResult("danger", "error-icon.svg", `
            <p class="error-title">❌ Invalid URL</p>
            <ul>
                <li>Please enter a valid URL to analyze.</li>
            </ul>
        `);
        return;
    }

    try {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            showResult("danger", "error-icon.svg", `
                <p class="error-title">❌ Missing Protocol</p>
                <ul>
                    <li>Please add 'http://' or 'https://' to the URL.</li>
                </ul>
            `);
            return;
        }

        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname;
        const tld = domain.split(".").pop();
        const isHttps = parsedUrl.protocol === "https:";

        // Check for valid TLD
        if (domain.split(".").length < 2) {
            showResult("danger", "error-icon.svg", `
                <p class="error-title">❌ Invalid URL</p>
                <ul>
                    <li>URL is missing a valid TLD (e.g., .com, .org).</li>
                </ul>
            `);
            return;
        }

        const trustedTlds = [
            "com", "org", "net", "edu", "gov", 
            "int", "mil", "co", "info", "name", 
            "pro", "us", "eu", "ca", "uk", 
            "de", "jp", "au", "fr", "it", 
            "nl", "se", "es", "ch", "be", 
            "at", "fi", "no", "dk", "cz"
        ];        
        const suspiciousTlds = [
            "tk", "ml", "ga", "cf", "gq", 
            "ru", "xyz", "top", "club", "win", 
            "date", "download", "pw", "space", 
            "work", "loan", "shop", "stream", 
            "buzz", "best", "link", "win", "click"
        ];        
        const suspiciousKeywords = [
            "free", "win", "prize", "gift", "click", 
            "verify", "update", "urgent", "limited", 
            "money", "reward", "claim", "winner", 
            "bonus", "exclusive", "instant", "guaranteed", 
            "promo", "offer", "cash", "contest", 
            "freebie", "freegift", "deal", "coupon", 
            "earn", "discount", "sale", "alert", 
            "emergency", "password", "login", "secure"
        ];
       
        let messages = [];
        let allGood = true;

        // Check HTTPS
        if (isHttps) {
            messages.push("✅ HTTPS is enabled (The link is secure).");
        } else {
            allGood = false;
            messages.push("⚠️ No HTTPS detected (The link is not secure).");
        }

        // Check TLD
        if (trustedTlds.includes(tld)) {
            messages.push(`✅ Domain is trusted (.${tld}).`);
        } else if (suspiciousTlds.includes(tld)) {
            allGood = false;
            messages.push(`⚠️ Suspicious domain (.${tld} TLD often associated with scams).`);
        } else {
            messages.push(`⚠️ Uncommon domain (.${tld}).`);
        }

        // Check Keywords
        const foundKeywords = suspiciousKeywords.filter(keyword => domain.includes(keyword));
        if (foundKeywords.length > 0) {
            allGood = false;
            messages.push(`⚠️ Contains red-flag keywords: "${foundKeywords.join('", "')}".`);
        } else {
            messages.push("✅ No suspicious keywords found.");
        }

        // Final Decision
        if (allGood) {
            showResult("safe", "safe-icon.svg", `
                <p class="safe-title">✅ Safe Link</p>
                <ul>
                    ${messages.map(msg => `<li>${msg}</li>`).join("")}
                </ul>
                <p class="safe-recommendation">✅ Recommendation: This link appears safe to visit.</p>
            `);
        } else {
            showResult("danger", "danger-icon.svg", `
                <p class="error-title">⚠️ Potential Scam</p>
                <ul>
                    ${messages.map(msg => `<li>${msg}</li>`).join("")}
                </ul>
                <p class="error-recommendation">⚠️ Recommendation: Avoid clicking this link. It could be a scam.</p>
            `);
        }
    } catch (e) {
        showResult("danger", "error-icon.svg", `
            <p class="error-title">❌ Invalid URL</p>
            <ul>
                <li>Please ensure the URL includes 'http://' or 'https://'.</li>
            </ul>
        `);
    }
}

// Check URL when pressing Enter key
urlInput.addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
        checkURL();
    }
});

// Check URL when clicking the paste button (if your paste button is a copy-to-clipboard type)
document.getElementById("pasteButton").addEventListener("click", function() {
    navigator.clipboard.readText().then(text => {
        urlInput.value = text;
        checkURL();
    });
});

checkButton.addEventListener("click", checkURL);
