
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

class URLChecker {
    constructor() {
        this.cache = new Map();
    }

    async checkURL(url) {
        // Check cache first
        const cachedResult = this.getFromCache(url);
        if (cachedResult) return cachedResult;

        // Perform enhanced checks
        const mlScore = enhancedURLCheck(url);
        const result = {
            timestamp: Date.now(),
            score: mlScore.risk,
            flags: mlScore.flags
        };

        // Cache the result
        this.cache.set(url, result);
        return result;
    }

    getFromCache(url) {
        if (!this.cache.has(url)) return null;
        
        const result = this.cache.get(url);
        if (Date.now() - result.timestamp > CACHE_DURATION) {
            this.cache.delete(url);
            return null;
        }
        return result;
    }
}
