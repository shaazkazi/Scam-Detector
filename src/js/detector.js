import { suspiciousKeywords, suspiciousTlds } from '../js/keywords.js';

const ML_PATTERNS = {
    suspicious_chars: /[<>{}\[\]]/,
    ip_address: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    excessive_subdomains: /(?:[^./]+\.){4,}/,
    phishing_patterns: /(?:paypa[l|l-]+|www-+|\d{3}-+|(?:login|verify|secure|account)[a-zA-Z0-9]*\.)/i,
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
        return { risk: 0, flags: ['Unable to check with Google Safe Browsing'] };
    }
}

async function enhancedURLCheck(url) {
    // Extended whitelist for legitimate domains
    const whitelist = [
        'facebook.com', 'www.facebook.com',
        'google.com', 'www.google.com',
        'instagram.com', 'www.instagram.com',
        'twitter.com', 'www.twitter.com', 'x.com',
        'linkedin.com', 'www.linkedin.com',
        'paypal.com', 'www.paypal.com',
        'amazon.com', 'www.amazon.com',
        'microsoft.com', 'www.microsoft.com',
        'apple.com', 'www.apple.com',
        'netflix.com', 'www.netflix.com',
        'youtube.com', 'www.youtube.com',
        'github.com', 'www.github.com',
        'openai.com', 'www.openai.com',
        'chatgpt.com', 'www.chatgpt.com',
        'wikipedia.org', 'www.wikipedia.org',
        'yahoo.com', 'www.yahoo.com',
        'bing.com', 'www.bing.com',
        'reddit.com', 'www.reddit.com',
        'pinterest.com', 'www.pinterest.com',
        'twitch.tv', 'www.twitch.tv',
        'spotify.com', 'www.spotify.com',
        'dropbox.com', 'www.dropbox.com',
        'gmail.com', 'mail.google.com'
    ];
    
    const score = {
        risk: 0,
        flags: [],
    };
    
    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname.toLowerCase();
        
        // Check if domain or any parent domain is in whitelist
        if (whitelist.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
            return {
                risk: 0,
                flags: ['Verified legitimate website']
            };
        }
        
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
        if (ML_PATTERNS.phishing_patterns.test(hostname)) {
            score.risk += 40;
            score.flags.push("Detected phishing pattern in domain");
        }
        
        // Check for suspicious brands (e.g., paypal, google, facebook)
        if (ML_PATTERNS.suspicious_brands.test(hostname)) {
            score.risk += 35;
            score.flags.push("Suspicious brand name in domain");
        }
        
        // Typo squatting detection
        if (ML_PATTERNS.typo_squatting.test(hostname)) {
            score.risk += 50;
            score.flags.push("Potential typo-squatting detected");
        }
        
        // Check for subdomain spoofing
        if (ML_PATTERNS.subdomain_spoofing.test(hostname)) {
            score.risk += 30;
            score.flags.push("Possible subdomain spoofing detected");
        }
        
        // Check for obfuscated characters in the URL
        if (ML_PATTERNS.obfuscated_chars.test(hostname)) {
            score.risk += 25;
            score.flags.push("Obfuscated characters detected in domain");
        }
        
        // Check for suspicious keywords - ONLY IN DOMAIN, not in path
        suspiciousKeywords.forEach((keyword) => {
            if (hostname.includes(keyword)) {
                score.risk += 15;
                score.flags.push(`Contains suspicious keyword in domain: ${keyword}`);
            }
        });
        
        // Check for suspicious TLDs
        suspiciousTlds.forEach((tld) => {
            if (hostname.endsWith(tld)) {
                score.risk += 20;
                score.flags.push(`Uses suspicious TLD: ${tld}`);
            }
        });
        
    } catch (e) {
        // If URL parsing fails, add risk
        score.risk += 20;
        score.flags.push("Invalid URL format");
    }
    
    // Call Google Safe Browsing API
    try {
        const googleResult = await checkGoogleSafeBrowsing(url);
        score.risk += googleResult.risk;
        score.flags = [...score.flags, ...googleResult.flags];
    } catch (error) {
        console.error("Error with Google Safe Browsing check:", error);
    }
    
    // If only one minor flag is triggered, reduce the risk
    if (score.flags.length === 1 && score.risk < 30) {
        score.risk = 0;
        score.flags = ['Low risk - passed enhanced security check'];
    }
    
    return score;
}

export default enhancedURLCheck;
