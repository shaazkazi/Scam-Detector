import enhancedURLCheck from './src/js/detector.js'; // Adjust the path as necessary

function isValidURL(url) {
    const pattern = /^(https?:\/\/)?([\w\d\-_]+\.)+[\w\d\-_]+(\/[\w\d\-_]+)*\/?$/;
    return pattern.test(url);
}

document.getElementById("checkButton").addEventListener("click", function () {
    const url = document.getElementById("urlInput").value; // Get the URL from input
    console.log("URL input: ", url); // Debugging: Check the entered URL

    if (url) {
        if (isValidURL(url)) {
            // Perform URL check
            console.log("Checking URL..."); // Debugging: Log when URL is being checked
            const result = enhancedURLCheck(url); // Call the function from your detector.js file
            console.log("Result: ", result); // Debugging: Log the result of the check
            displayResult(result); // Display the result
        } else {
            alert("Please enter a valid URL.");
        }
    } else {
        alert("Please enter a URL to check.");
    }
});

function displayResult(result) {
    const resultIcon = document.getElementById("resultIcon");
    const resultMessage = document.getElementById("resultMessage");

    if (result.risk > 0) {
        resultIcon.src = "/assets/icons/warning-icon.svg"; // Updated path to the warning icon
        resultMessage.innerText = `Risk Level: ${result.risk} \n Flags: ${result.flags.join(", ")}`;
    } else {
        resultIcon.src = "/assets/icons/success-icon.svg"; // Updated path to the success icon
        resultMessage.innerText = "URL is safe!";
    }

    document.getElementById("result").style.display = "block"; // Show result container
}
