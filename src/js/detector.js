const ML_PATTERNS = {
    suspicious_chars: /[<>{}\[\]]/,
    ip_address: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    excessive_subdomains: /(?:[^./]+\.){4,}/,
    phishing_patterns: /(?:paypa[l|l-]+|www-+|\d{3}-+|[a-zA-Z0-9]{5,}\.com)/i,
    suspicious_brands: /(?:payp[a|l]|googl[e|es]|facebo[o|ok])/i,

    // Enhanced typo-squatting regex with numeric replacements for common letters like "o", "l", "g", etc.
    typo_squatting: /([g0]{2}|[o0]{2}|[l1]{2}|[e3]{2}|[a4]{2})[a-zA-Z0-9]+\.[a-zA-Z]{2,}/i,

    // Subdomain spoofing detection
    subdomain_spoofing: /(?:[a-zA-Z0-9]{2,}\.)?(payp[a|l]|googl[e|es]|facebo[o|ok])\./i,

    // Obfuscation detection: looks for numbers replacing letters
    obfuscated_chars: /(?:[a-zA-Z]{1}[0-9]{1}|[0-9]{1}[a-zA-Z]{1})/i,
};

// Google Safe Browsing API Key and Client ID
const API_KEY = 'AIzaSyAj9HXId4hOlc3hI9Q1fC1WowV_HgEobh4'; // Replace with your API key
const CLIENT_ID = 'safe-447019'; // Replace with your client ID

async function checkGoogleSafeBrowsing(url) {
    const endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
    const requestBody = {
        client: {
            clientId: CLIENT_ID,
            clientVersion: '1.0'
        },
        threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [
                {
                    url: url
                }
            ]
        }
    };

    try {
        const response = await axios.post(`${endpoint}?key=${API_KEY}`, requestBody);
        
        // If any matches are found, it is flagged
        if (response.data.matches && response.data.matches.length > 0) {
            return { risk: 50, flags: ['Flagged by Google Safe Browsing'] };
        } else {
            return { risk: 0, flags: ['Safe according to Google Safe Browsing'] };
        }
    } catch (error) {
        console.error('Error checking Google Safe Browsing:', error);
        return { risk: 100, flags: ['Error checking Google Safe Browsing'] };
    }
}

async function enhancedURLCheck(url) {
    const score = {
        risk: 0,
        flags: [],
    };

    // Check for suspicious characters
    if (ML_PATTERNS.suspicious_chars.test(url)) {
        score.risk += 30;
        score.flags.push("Contains suspicious characters");
    }

    // Check for IP address instead of domain
    if (ML_PATTERNS.ip_address.test(url)) {
        score.risk += 25;
        score.flags.push("Uses IP address instead of domain name");
    }

    // Check for excessive subdomains
    if (ML_PATTERNS.excessive_subdomains.test(url)) {
        score.risk += 20;
        score.flags.push("Contains excessive subdomains");
    }

    // Phishing pattern detection
    if (ML_PATTERNS.phishing_patterns.test(url)) {
        score.risk += 40;
        score.flags.push("Detected phishing pattern in URL");
    }

    // Check for suspicious brands (e.g., paypal, google, facebook)
    if (ML_PATTERNS.suspicious_brands.test(url)) {
        score.risk += 35;
        score.flags.push("Suspicious brand name in URL");
    }

    // Typo squatting detection (now with better handling of numeric obfuscation)
    if (ML_PATTERNS.typo_squatting.test(url)) {
        score.risk += 50;
        score.flags.push("Potential typo-squatting detected");
    }

    // Check for subdomain spoofing
    if (ML_PATTERNS.subdomain_spoofing.test(url)) {
        score.risk += 30;
        score.flags.push("Possible subdomain spoofing detected");
    }

    // Check for obfuscated characters in the URL
    if (ML_PATTERNS.obfuscated_chars.test(url)) {
        score.risk += 25;
        score.flags.push("Obfuscated characters detected in URL");
    }

    // Check for suspicious keywords
    suspiciousKeywords.forEach((keyword) => {
        if (url.toLowerCase().includes(keyword)) {
            score.risk += 15;
            score.flags.push(`Contains suspicious keyword: ${keyword}`);
        }
    });

    // Check for suspicious TLDs
    suspiciousTLDs.forEach((tld) => {
        if (url.endsWith(tld)) {
            score.risk += 20;
            score.flags.push(`Uses suspicious TLD: ${tld}`);
        }
    });

    // Call Google Safe Browsing API
    const googleResult = await checkGoogleSafeBrowsing(url);
    score.risk += googleResult.risk;
    score.flags = [...score.flags, ...googleResult.flags];

    return score;
}

export default enhancedURLCheck;
