// Import necessary modules
import { suspiciousKeywords, suspiciousTlds, trustedTlds } from './src/js/keywords.js';
import enhancedURLCheck from './src/js/detector.js';

// Debug logging to make sure script loads
console.log("Script loading...");

document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM fully loaded");

    // DOM element references
    const urlInput = document.getElementById("urlInput");
    const checkButton = document.getElementById("checkButton");
    const pasteButton = document.getElementById("pasteButton");
    const resultCard = document.getElementById("result");
    const resultTitle = document.getElementById("resultTitle");
    const resultMessage = document.getElementById("resultMessage");
    const resultIcon = document.getElementById("resultIcon");
    const themeToggle = document.getElementById("toggleTheme");
    const themeIcon = document.getElementById("themeIcon");
    const loadingIndicator = document.getElementById("loadingIndicator");
    const historyDiv = document.getElementById("historyDiv");
    const modal = document.getElementById("infoModal");
    const modalText = document.getElementById("modalText");
    const closeButton = document.querySelector(".close-button");
    const ratingFill = document.getElementById('ratingFill');
    const ratingValue = document.getElementById('ratingValue');
    const shareButton = document.getElementById('shareButton');

    // Log DOM elements to verify they exist
    console.log("URL input element:", urlInput);
    console.log("Result card element:", resultCard);

    // Application state
    let isDarkMode = true;
    let urlHistory = JSON.parse(localStorage.getItem('urlHistory') || '[]');

    // Initialize theme
    if (localStorage.getItem('theme') === 'light') {
        isDarkMode = false;
        document.body.classList.remove("dark-mode");
        themeIcon.innerHTML = `
            <path fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        `;
    } else {
        document.body.classList.add("dark-mode");
    }

    // Hide the loader by default
    loadingIndicator.style.display = "none";

    // Function to update the rating display
    function updateRatingDisplay(score) {
        // Inverse the score for safety rating (100 - risk)
        const safetyScore = Math.max(0, Math.min(100, 100 - score));
        
        // Update the text value
        ratingValue.textContent = Math.round(safetyScore);
        
        // Update the fill width
        ratingFill.style.width = `${safetyScore}%`;
        
        // Set appropriate color class based on rating
        ratingFill.className = 'rating-fill';
        if (safetyScore >= 90) {
            ratingFill.classList.add('excellent');
        } else if (safetyScore >= 70) {
            ratingFill.classList.add('good');
        } else if (safetyScore >= 40) {
            ratingFill.classList.add('moderate');
        } else {
            ratingFill.classList.add('poor');
        }
    }

    // Toggle theme between dark and light mode
    function toggleTheme() {
        isDarkMode = !isDarkMode;
        document.body.classList.toggle("dark-mode", isDarkMode);
        
        if (isDarkMode) {
            themeIcon.innerHTML = `
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            `;
            localStorage.setItem('theme', 'dark');
        } else {
            themeIcon.innerHTML = `
                <path fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
            `;
            localStorage.setItem('theme', 'light');
        }
    }

    // Show the result of URL check
    function showResult(status, icon, message, riskScore = 0) {
        resultCard.style.display = "flex";
        resultCard.className = `result-card ${status}`;
        resultIcon.src = icon;
        resultIcon.alt = status === "safe" ? "Safe Icon" : "Danger Icon";
        resultTitle.textContent = status === "safe" ? "Safe Website" : "Potential Scam";
        resultMessage.innerHTML = message;
        loadingIndicator.style.display = "none";
        
        // Update the rating display
        updateRatingDisplay(riskScore);
        
        // Show share button
        shareButton.style.display = "flex";
        
        // Scroll to result with smooth animation
        resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Function to check DNS for suspicious patterns
    function checkDNS(domain) {
        const whitelist = ['www.facebook.com', 'facebook.com', 'www.google.com', 'google.com'];
        if (whitelist.includes(domain.toLowerCase())) {
            return [];
        }
        const dnsWarnings = [];
        
        const suspiciousPatterns = {
            repeatedChars: /(?!www)(.)\1{3,}/, 
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
            dnsWarnings.push("⚠️ Whoa, this domain is speaking in a language I don't understand. Non-ASCII characters spotted.");
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

    // Function to share results as image
function shareResults() {
    // Get the URL that was scanned
    const scannedUrl = urlInput.value.trim();
   
    // Create a container for the result to be captured
    const container = document.createElement('div');
    container.className = 'share-canvas-container';
   
    // Create an element to display the scanned URL
    const urlDisplay = document.createElement('div');
    urlDisplay.style.padding = '12px';
    urlDisplay.style.backgroundColor = isDarkMode ? '#1E293B' : '#F1F5F9';
    urlDisplay.style.borderRadius = '8px 8px 0 0';
    urlDisplay.style.border = isDarkMode ? '1px solid #334155' : '1px solid #E2E8F0';
    urlDisplay.style.borderBottom = 'none';
    urlDisplay.style.fontWeight = 'bold';
    urlDisplay.style.wordBreak = 'break-all';
    urlDisplay.style.color = isDarkMode ? '#F1F5F9' : '#1E293B';
    urlDisplay.style.fontSize = '14px';
    urlDisplay.innerHTML = `
        <div style="margin-bottom:6px;color:${isDarkMode ? '#94A3B8' : '#64748B'};font-size:12px;">ANALYZED URL:</div>
        ${scannedUrl}
    `;
   
    // Create a clean version of the result card instead of cloning it
    const cleanResultCard = document.createElement('div');
    cleanResultCard.className = resultCard.className;
    cleanResultCard.style.borderRadius = '0 0 8px 8px';
    
    // Copy only the necessary content
    const iconContainer = document.createElement('div');
    iconContainer.className = 'result-icon-container';
    const resultIconClone = document.createElement('img');
    resultIconClone.src = resultIcon.src;
    resultIconClone.alt = resultIcon.alt;
    resultIconClone.className = resultIcon.className;
    iconContainer.appendChild(resultIconClone);
    
    const contentContainer = document.createElement('div');
    contentContainer.className = 'result-content';
    
    const titleElement = document.createElement('h3');
    titleElement.textContent = resultTitle.textContent;
    contentContainer.appendChild(titleElement);
    
    // Add the rating container
    const ratingContainer = document.createElement('div');
    ratingContainer.className = 'rating-container';
    
    const ratingMeter = document.createElement('div');
    ratingMeter.className = 'rating-meter';
    
    const ratingFillClone = document.createElement('div');
    ratingFillClone.className = ratingFill.className;
    ratingFillClone.style.width = ratingFill.style.width;
    ratingMeter.appendChild(ratingFillClone);
    
    const ratingScoreElement = document.createElement('div');
    ratingScoreElement.className = 'rating-score';
    ratingScoreElement.innerHTML = `<span>${ratingValue.textContent}</span><span>/100</span>`;
    
    ratingContainer.appendChild(ratingMeter);
    ratingContainer.appendChild(ratingScoreElement);
    contentContainer.appendChild(ratingContainer);
    
    // Add the result message
    const messageDiv = document.createElement('div');
    messageDiv.innerHTML = resultMessage.innerHTML;
    contentContainer.appendChild(messageDiv);
    
    // Assemble the clean result card
    cleanResultCard.appendChild(iconContainer);
    cleanResultCard.appendChild(contentContainer);
   
    // Add URL display and clean result to container
    container.appendChild(urlDisplay);
    container.appendChild(cleanResultCard);
   
    // Add branding to the bottom
    const branding = document.createElement('div');
    branding.style.textAlign = 'center';
    branding.style.padding = '8px';
    branding.style.color = isDarkMode ? '#94A3B8' : '#64748B';
    branding.style.fontSize = '12px';
    branding.style.marginTop = '8px';
    branding.innerHTML = 'Scanned with Scam Detect, Created by Shaaz Kazi';
    container.appendChild(branding);
   
    // Add the container to body
    document.body.appendChild(container);
   
    // Use html2canvas to capture the result as an image
    html2canvas(container, {
        backgroundColor: isDarkMode ? '#0F172A' : '#F8FAFC',
        scale: 2, // Higher resolution
        useCORS: true, // Allow images from other domains
        logging: false // Reduce console noise
    }).then(canvas => {
        // Remove the temporary container
        document.body.removeChild(container);
       
        // Convert canvas to blob
        canvas.toBlob(function(blob) {
            // Create file from blob
            const file = new File([blob], 'url-check-result.png', { type: 'image/png' });
           
            // Check if Web Share API is available
            if (navigator.share && navigator.canShare({ files: [file] })) {
                navigator.share({
                    title: 'URL Check Result',
                    text: 'Check out this URL analysis result from Scam Detect! visit https://scamdetect.netlify.app to scan your own URLs.',
                    files: [file]
                }).then(() => {
                    showShareTooltip('Shared successfully!');
                }).catch(error => {
                    console.error('Error sharing:', error);
                    downloadImage(canvas);
                });
            } else {
                // Fallback - download the image
                downloadImage(canvas);
            }
        });
    }).catch(error => {
        console.error('Error generating image:', error);
        alert('Failed to generate image for sharing.');
    });
}

    
        // Function to download canvas as image
        function downloadImage(canvas) {
            const link = document.createElement('a');
            link.download = 'url-check-result.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
            showShareTooltip('Image downloaded!');
        }
        
        // Function to show share tooltip
        function showShareTooltip(message) {
            const tooltip = document.createElement('div');
            tooltip.className = 'share-tooltip';
            tooltip.textContent = message;
            document.body.appendChild(tooltip);
            
            // Remove tooltip after animation completes
            setTimeout(() => {
                document.body.removeChild(tooltip);
            }, 3000);
        }
    
        async function checkURL() {
            console.log("checkURL function called");
            let url = urlInput.value.trim();
    
            // Hide share button when starting a new check
            shareButton.style.display = "none";
    
            // Convert the protocol (http or https) to lowercase
            if (url.startsWith("http://")) {
                url = "http://" + url.slice(7).toLowerCase();
            } else if (url.startsWith("https://")) {
                url = "https://" + url.slice(8).toLowerCase();
            }
    
            if (!url) {
                showResult("danger", "/error-icon.svg", `
                    <div class="result-message">
                        <p class="error-title">⚠️ Hmm... Something's missing here.</p>
                        <ul>
                            <li>Did you forget to enter a URL? Go ahead, try again.</li>
                        </ul>
                    </div>
                `, 0);
                return;
            }
    
            try {
                // Show loader before starting the check
                loadingIndicator.style.display = "flex";
                resultCard.style.display = "none";
    
                // Check if URL has a protocol (http:// or https://)
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    showResult("danger", "/error-icon.svg", `
                        <div class="result-message">
                            <p class="error-title">⚠️ Oh no, no protocol?</p>
                            <ul>
                                <li>Please add 'http://' or 'https://' in front of the URL. It's not that hard.</li>
                            </ul>
                        </div>
                    `, 30);
                    return;
                }
    
                const parsedUrl = new URL(url);
                const domain = parsedUrl.hostname;
                const tld = domain.split(".").pop();
                const isHttps = parsedUrl.protocol === "https:";
    
                let messages = [];
                let allGood = true;
                let riskScore = 0;
    
                if (isHttps) {
                    messages.push("✅ HTTPS is enabled. Stay secure and classy.");
                } else {
                    allGood = false;
                    messages.push("⚠️ No HTTPS? Not Secured.");
                    riskScore += 15;
                }
    
                // Get all warnings BEFORE checking them
                const dnsWarnings = checkDNS(domain);
                const redirectWarnings = checkRedirects(url);
                const foundKeywords = suspiciousKeywords.filter(keyword => domain.includes(keyword));
                
                // Now check each warning type
                if (dnsWarnings.length > 0) {
                    allGood = false;
                    messages.push(...dnsWarnings);
                    riskScore += dnsWarnings.length * 10;
                }
    
                if (redirectWarnings.length > 0) {
                    allGood = false;
                    messages.push(...redirectWarnings);
                    riskScore += 20;
                }
    
                if (suspiciousTlds.includes(`.${tld}`)) {
                    allGood = false;
                    messages.push(`⚠️ The domain ends with .${tld} — a red flag for scams. Proceed with caution.`);
                    riskScore += 25;
                } else {
                    messages.push(`✅ This domain's TLD is trustworthy. (.${tld})`);
                }
    
                if (foundKeywords.length > 0) {
                    allGood = false;
                    messages.push(`⚠️ Keywords like "${foundKeywords.join('", "')}"? Sounds fishy.`);
                    riskScore += foundKeywords.length * 15;
                } else {
                    messages.push("✅ No suspicious keywords found. It's like a breath of fresh air.");
                }
    
                // Also perform the enhanced URL check
                try {
                    const enhancedResult = await enhancedURLCheck(url);
                    if (enhancedResult.risk > 0) {
                        allGood = false;
                        messages.push(`⚠️ Enhanced security check flagged this URL (Risk: ${enhancedResult.risk})`);
                        messages.push(...enhancedResult.flags.map(flag => `⚠️ ${flag}`));
                        riskScore += enhancedResult.risk;
                    } else {
                        messages.push("✅ Enhanced security check passed.");
                    }
                } catch (error) {
                    console.error("Error performing enhanced check:", error);
                }
    
                // Ensure risk score is capped at 100
                riskScore = Math.min(100, riskScore);
    
                // Add a 1-second delay before showing the result
                setTimeout(() => {
                    if (allGood) {
                        showResult("safe", "/safe-icon.svg", `
                            <div class="result-message">
                                <p class="safe-title">✅ Congratulations, You Found a Safe Link!</p>
                                <ul>
                                    ${messages.map(msg => `<li>${msg}</li>`).join("")}
                                </ul>
                                <p class="safe-recommendation">✅ My recommendation: Go ahead, click it, I guess.</p>
                            </div>
                        `, riskScore);
                    } else {
                        showResult("danger", "/danger-icon.svg", `
                            <div class="result-message">
                                <p class="error-title">⚠️ Potential Scam, Do Not Click!</p>
                                <ul>
                                    ${messages.map(msg => `<li>${msg}</li>`).join("")}
                                </ul>
                                <p class="error-recommendation">⚠️ Avoid this link, This is a scam.</p>
                            </div>
                        `, riskScore);
                    }
    
                    // Update history after checking the URL
                    updateHistory(url);
                }, 1000);  // 1-second delay
            } catch (e) {
                console.error("Error checking URL:", e);
                showResult("danger", "/error-icon.svg", `
                    <div class="result-message">
                        <p class="error-title">❌ Invalid URL</p>
                        <ul>
                            <li>Let's not be dramatic, just make sure you enter a proper URL next time.</li>
                        </ul>
                    </div>
                `, 50);
            } finally {
                // Ensure the loader is visible for at least 1 second before being hidden
                setTimeout(() => {
                    loadingIndicator.style.display = "none";
                }, 1000);  // 1-second delay before hiding the loader
            }
        }
    
        // Function to display URL history
        function displayHistory() {
            historyDiv.innerHTML = urlHistory.map(historyUrl => `
                <div class="history-item">
                    <span class="history-url" data-url="${historyUrl}">${historyUrl}</span>
                    <button class="copy-button" aria-label="Copy URL" data-url="${historyUrl}">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="copy-icon">
                                                    <path d="M8 4V16C8 16.5304 8.21071 17.0391 8.58579 17.4142C8.96086 17.7893 9.46957 18 10 18H18C18.5304 18 19.0391 17.7893 19.4142 17.4142C19.7893 17.0391 20 16.5304 20 16V7.242C20 6.97556 19.9467 6.71181 19.8433 6.46624C19.7399 6.22068 19.5885 5.99824 19.398 5.812L16.188 2.602C16.0018 2.41148 15.7793 2.26012 15.5338 2.15673C15.2882 2.05334 15.0244 2.00001 14.758 2H10C9.46957 2 8.96086 2.21071 8.58579 2.58579C8.21071 2.96086 8 3.46957 8 4Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M16 18V20C16 20.5304 15.7893 21.0391 15.4142 21.4142C15.0391 21.7893 14.5304 22 14 22H6C5.46957 22 4.96086 21.7893 4.58579 21.4142C4.21071 21.0391 4 20.5304 4 20V8C4 7.46957 4.21071 6.96086 4.58579 6.58579C4.96086 6.21071 5.46957 6 6 6H8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                </div>
            `).join('');
    
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
                    const urlToCopy = e.currentTarget.dataset.url;
                    navigator.clipboard.writeText(urlToCopy).then(() => {
                        // Show success icon after copying
                        const successIcon = `
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="success-icon">
                                <path d="M5 12L10 17L20 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        `;
                        button.innerHTML = successIcon;
                        setTimeout(() => {
                            button.innerHTML = `
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="copy-icon">
                                    <path d="M8 4V16C8 16.5304 8.21071 17.0391 8.58579 17.4142C8.96086 17.7893 9.46957 18 10 18H18C18.5304 18 19.0391 17.7893 19.4142 17.4142C19.7893 17.0391 20 16.5304 20 16V7.242C20 6.97556 19.9467 6.71181 19.8433 6.46624C19.7399 6.22068 19.5885 5.99824 19.398 5.812L16.188 2.602C16.0018 2.41148 15.7793 2.26012 15.5338 2.15673C15.2882 2.05334 15.0244 2.00001 14.758 2H10C9.46957 2 8.96086 2.21071 8.58579 2.58579C8.21071 2.96086 8 3.46957 8 4Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <path d="M16 18V20C16 20.5304 15.7893 21.0391 15.4142 21.4142C15.0391 21.7893 14.5304 22 14 22H6C5.46957 22 4.96086 21.7893 4.58579 21.4142C4.21071 21.0391 4 20.5304 4 20V8C4 7.46957 4.21071 6.96086 4.58579 6.58579C4.96086 6.21071 5.46957 6 6 6H8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            `;
                        }, 1000); // Reset copy icon after 1 second
                    }).catch(err => {
                        console.error('Failed to copy text: ', err);
                    });
                });
            });
        }
    
            // Update history with clickable URLs and copy functionality
    function updateHistory(url) {
        // Add URL to history if it's not already there and it's a string
        if (typeof url === 'string' && !urlHistory.includes(url)) {
            urlHistory.unshift(url); // Add to the beginning
            // Keep only the latest 10 URLs
            if (urlHistory.length > 10) {
                urlHistory.pop();
            }
            // Save to localStorage
            localStorage.setItem('urlHistory', JSON.stringify(urlHistory));
        }
        
        // Update the history UI
        displayHistory();
    }

    // Initialize history display on page load
    displayHistory();                    

    // Event listeners - Multiple approaches to ensure Enter key works properly
    urlInput.addEventListener("keydown", function(event) {
        if (event.key === "Enter") {
            event.preventDefault(); // Prevent default form submission
            checkURL();
        }
    });

    pasteButton.addEventListener("click", function() {
        navigator.clipboard.readText()
            .then(text => {
                urlInput.value = text;
                checkURL();
            })
            .catch(e => {
                console.error("Failed to paste clipboard contents", e);
                alert("Could not access clipboard. Please manually paste the URL.");
            });
    });

    themeToggle.addEventListener("click", toggleTheme);
    checkButton.addEventListener("click", checkURL);
    
    // Add event listener for the share button
    shareButton.addEventListener("click", shareResults);

    // Modal functionality
    resultIcon.addEventListener("click", function() {
        const status = resultCard.classList.contains("safe") ? "safe" : "danger";
        const ratingScore = ratingValue.textContent;
        
        if (status === "safe") {
            modalText.innerHTML = `This website is verified as safe by our security systems with a safety rating of <strong>${ratingScore}/100</strong>. You can continue browsing without any concerns.`;
        } else {
            modalText.innerHTML = `This website is flagged as a scam with a safety rating of only <strong>${ratingScore}/100</strong>. Avoid clicking any links or providing personal information.`;
        }
        
        modal.style.display = "flex";
        modal.classList.add("visible");
    });

    closeButton.addEventListener("click", function() {
        modal.classList.remove("visible");
        setTimeout(() => {
            modal.style.display = "none";
        }, 300);
    });

    modal.addEventListener("click", function(event) {
        if (event.target === modal) {
            modal.classList.remove("visible");
            setTimeout(() => {
                modal.style.display = "none";
            }, 300);
        }
    });

    // Fallback for Enter key - add to document level
    document.addEventListener("keydown", function(event) {
        if (event.key === "Enter" && document.activeElement === urlInput) {
            event.preventDefault();
            checkURL();
        }
    });

    console.log("All event listeners successfully attached");
});
