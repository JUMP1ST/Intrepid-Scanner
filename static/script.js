// Theme toggle
document.getElementById('themeToggle').addEventListener('click', function() {
    document.body.classList.toggle('dark-mode');
    document.body.classList.toggle('light-mode');
    this.innerHTML = document.body.classList.contains('dark-mode') ? '<i class="bi bi-sun"></i>' : '<i class="bi bi-moon"></i>';
});

// Handle tab clicks and form display
const tabs = document.querySelectorAll('.tab-link');
const contents = document.querySelectorAll('.tab-content');
const underline = document.querySelector('.tab-underline');

tabs.forEach((tab, index) => {
    tab.addEventListener('click', function(e) {
        e.preventDefault();
        
        // Remove active class from all tabs and content
        tabs.forEach(t => t.classList.remove('active'));
        contents.forEach(c => c.classList.remove('active'));

        // Add active class to clicked tab and respective content
        this.classList.add('active');
        contents[index].classList.add('active');

        // Update the underline to match the active tab's width and position
        const tabWidth = this.offsetWidth;
        const tabPosition = this.offsetLeft;
        underline.style.width = `${tabWidth}px`;
        underline.style.transform = `translateX(${tabPosition}px)`;
    });
});

// Set initial active tab and content
tabs[0].classList.add('active');
contents[0].classList.add('active');
underline.style.width = `${tabs[0].offsetWidth}px`;
underline.style.transform = `translateX(${tabs[0].offsetLeft}px)`;


// Function to check scan status and findings
function checkScanAndAlert() {
    fetch('/scan-status')
        .then(response => response.json())
        .then(data => {
            const alertIcon = document.querySelector('.alert-icon');

            // Check if a scan has been completed and if findings exist
            if (data.scan_completed) {
                if (data.findings_exist) {
                    // Show an alert indicating findings exist
                    alert("A scan has completed and findings are available for review.");
                } else {
                    // Alert for scan completion without findings
                    alert("Scan completed. No findings detected.");
                }
                // Optionally highlight the alert icon
                alertIcon.classList.add('alert-highlight');
            }
        })
        .catch(error => console.error('Error checking scan status:', error));
}

// Periodically check scan status and findings every 5 seconds
setInterval(checkScanAndAlert, 5000);
