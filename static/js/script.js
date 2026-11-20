/**
 * SECUREGUARD - Web Application Security Testing System
 * Frontend Controller & API Integration
 */

console.log("SECUREGUARD JAVASCRIPT INITIALIZING...");

/**
 * Handles legacy and cross-module calls to openFeature.
 * Resolves any errors when navigating to features section or modules.
 */
function openFeature(feature) {
    if (!feature) {
        showModule("home");
        return;
    }

    const normalized = feature.toLowerCase().trim();

    if (normalized === "features") {
        showModule("home", false);
        const featuresEl = document.getElementById("features");
        if (featuresEl) {
            featuresEl.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        return;
    }

    showModule(normalized);
}

/**
 * Switch active page view and synchronize navbar states.
 * @param {string} moduleName - Name or alias of the section to show.
 * @param {boolean} updateHash - Whether to update browser URL hash.
 */
function showModule(moduleName, updateHash = true) {
    if (!moduleName) moduleName = "home";

    let target = moduleName.toLowerCase().trim();

    // Map common aliases
    if (target === "features") {
        openFeature("features");
        return;
    }
    if (target === "sql_injection" || target === "sqli" || target === "sql-injection") {
        target = "sql";
    } else if (target === "xss_detection" || target === "xss-detection") {
        target = "xss";
    } else if (target === "report" || target === "history") {
        target = "reports";
    } else if (target === "analytics") {
        target = "analysis";
    }

    // Hide all pages
    const pages = document.querySelectorAll(".page");
    pages.forEach(page => {
        page.classList.remove("active");
    });

    let selected = document.getElementById(target);
    if (!selected) {
        console.warn(`Module "${target}" not found. Falling back to "home".`);
        target = "home";
        selected = document.getElementById("home");
    }

    if (selected) {
        selected.classList.add("active");
        window.scrollTo({ top: 0, behavior: "smooth" });
    }

    // Update active nav links
    document.querySelectorAll(".nav-links a").forEach(link => {
        const navTarget = link.getAttribute("data-nav");
        if (navTarget === target) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });

    // Update URL hash for bookmarking and history support
    if (updateHash && window.location.hash !== "#" + target) {
        history.pushState(null, "", "#" + target);
    }

    // Auto-refresh data when opening relevant modules
    if (target === "dashboard" || target === "analysis") {
        refreshData();
    } else if (target === "reports") {
        loadReports();
    }
}

/**
 * Populate textarea with sample test inputs for quick evaluation.
 */
function setSampleInput(type, sampleValue) {
    const textareaId = type === "sql" ? "sqlInput" : "xssInput";
    const textarea = document.getElementById(textareaId);
    if (textarea) {
        textarea.value = sampleValue;
        textarea.focus();
    }
}

/**
 * Clear textarea and reset result box.
 */
function clearInput(type) {
    const textareaId = type === "sql" ? "sqlInput" : "xssInput";
    const resultId = type === "sql" ? "sqlResult" : "xssResult";

    const textarea = document.getElementById(textareaId);
    if (textarea) textarea.value = "";

    const resultBox = document.getElementById(resultId);
    if (resultBox) {
        resultBox.classList.remove("visible", "risk-high-box", "risk-medium-box", "risk-low-box");
        resultBox.replaceChildren();
    }
}

/**
 * Send test payload to the Flask backend and render the security assessment.
 * @param {string} type - 'sql' or 'xss'
 */
async function runTest(type) {
    const inputElement = document.getElementById(type === "sql" ? "sqlInput" : "xssInput");
    const resultElement = document.getElementById(type === "sql" ? "sqlResult" : "xssResult");
    const testBtn = document.getElementById(type === "sql" ? "sqlTestBtn" : "xssTestBtn");

    if (!inputElement || !resultElement) {
        console.error("Test elements not found for type:", type);
        return;
    }

    const input = inputElement.value.trim();

    if (!input) {
        alert("Please enter a test input string or select one of the quick test samples!");
        inputElement.focus();
        return;
    }

    // Loading state
    if (testBtn) testBtn.disabled = true;
    resultElement.className = "result-box visible";
    resultElement.textContent = "Analyzing input pattern against security signatures...";

    try {
        const response = await fetch("/api/test", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                type: type,
                input: input
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Testing failed. Please check the backend connection.");
        }

        renderTestResult(resultElement, data);

        // Update statistics in the background
        refreshData();

    } catch (error) {
        resultElement.className = "result-box visible risk-high-box";
        resultElement.replaceChildren();

        const errHeading = document.createElement("h3");
        errHeading.textContent = "Test Request Failed";
        errHeading.className = "risk-high";

        const errDesc = document.createElement("p");
        errDesc.textContent = error.message;

        resultElement.append(errHeading, errDesc);
    } finally {
        if (testBtn) testBtn.disabled = false;
    }
}

/**
 * Render structured security assessment cards.
 */
function renderTestResult(container, data) {
    container.replaceChildren();

    const risk = data.risk || "Low";
    const riskClass = risk === "High" ? "risk-high" : (risk === "Medium" ? "risk-medium" : "risk-low");
    const badgeClass = risk === "High" ? "badge-high" : (risk === "Medium" ? "badge-medium" : "badge-low");
    const boxRiskClass = risk === "High" ? "risk-high-box" : (risk === "Medium" ? "risk-medium-box" : "risk-low-box");

    container.className = `result-box visible ${boxRiskClass}`;

    // Header: Status + Risk Badge
    const header = document.createElement("div");
    header.className = "result-header";

    const title = document.createElement("h3");
    title.textContent = data.status;
    title.className = riskClass;

    const badge = document.createElement("span");
    badge.className = `badge ${badgeClass}`;
    badge.textContent = `${risk} Risk`;

    header.append(title, badge);

    // Details Body
    const details = document.createElement("div");
    details.className = "result-details";

    if (data.rule && data.rule !== "Safe Input") {
        const rulePara = document.createElement("p");
        rulePara.innerHTML = `<strong>Matched Pattern:</strong> ${escapeHtml(data.rule)}`;
        details.appendChild(rulePara);
    }

    const datePara = document.createElement("p");
    datePara.innerHTML = `<strong>Timestamp:</strong> ${escapeHtml(data.created_at || "")}`;
    details.appendChild(datePara);

    // Recommendation Box
    const recBox = document.createElement("div");
    recBox.className = "result-recommendation";
    recBox.innerHTML = `<strong>Security Recommendation:</strong><br>${escapeHtml(data.recommendation)}`;

    container.append(header, details, recBox);
}

/**
 * Fetch and update dashboard & analysis statistics from /api/stats.
 */
async function refreshData() {
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) throw new Error("Failed to load statistics.");

        const data = await response.json();

        // Update Dashboard counters
        const totalEl = document.getElementById("totalTests");
        const highEl = document.getElementById("highRisk");
        const medEl = document.getElementById("mediumRisk");
        const lowEl = document.getElementById("lowRisk");
        const scoreEl = document.getElementById("securityScore");
        const analysisScoreEl = document.getElementById("analysisScore");

        if (totalEl) totalEl.textContent = data.total;
        if (highEl) highEl.textContent = data.high;
        if (medEl) medEl.textContent = data.medium;
        if (lowEl) lowEl.textContent = data.low;

        const scoreText = (data.score !== undefined ? data.score : 100) + "/100";
        if (scoreEl) scoreEl.textContent = scoreText;
        if (analysisScoreEl) analysisScoreEl.textContent = scoreText;

        // Render Security Analysis Summary
        renderAnalysisSummary(data);

    } catch (error) {
        console.error("Dashboard stats error:", error);
    }
}

/**
 * Render comprehensive analysis summary view.
 */
function renderAnalysisSummary(data) {
    const summaryContainer = document.getElementById("analysisSummary");
    if (!summaryContainer) return;

    summaryContainer.replaceChildren();

    const total = data.total || 0;
    const high = data.high || 0;
    const medium = data.medium || 0;
    const low = data.low || 0;
    const score = data.score !== undefined ? data.score : 100;

    let postureTitle = "Optimal Security Posture";
    let postureClass = "risk-low";
    let postureDesc = "No high-risk vulnerabilities have been identified in current test inputs. Continue following defensive coding practices.";

    if (total === 0) {
        postureTitle = "System Initialized - Ready for Testing";
        postureClass = "risk-low";
        postureDesc = "No security tests have been recorded yet. Run SQL Injection and XSS tests to generate an active vulnerability profile.";
    } else if (high > 0) {
        postureTitle = "Vulnerabilities Detected - Remediation Required";
        postureClass = "risk-high";
        postureDesc = `Detected ${high} high-risk attack pattern(s). Input strings contain critical injection signatures requiring immediate sanitization and parameterized queries.`;
    } else if (medium > 0) {
        postureTitle = "Moderate Risk Warnings Present";
        postureClass = "risk-medium";
        postureDesc = `Found ${medium} medium-risk indicator(s). Ensure strict contextual output encoding and input validation are active across all endpoints.`;
    }

    // Posture overview box
    const postureBox = document.createElement("div");
    postureBox.className = "posture-box";
    postureBox.innerHTML = `
        <h3 class="${postureClass}">✦ ${postureTitle}</h3>
        <p>${postureDesc}</p>
    `;

    // Metrics grid
    const grid = document.createElement("div");
    grid.className = "analysis-grid";
    grid.innerHTML = `
        <div class="analysis-card">
            <h4>Total Executions</h4>
            <div class="val">${total}</div>
        </div>
        <div class="analysis-card">
            <h4>SQL Tests</h4>
            <div class="val">${data.sql_count || 0}</div>
        </div>
        <div class="analysis-card">
            <h4>XSS Tests</h4>
            <div class="val">${data.xss_count || 0}</div>
        </div>
        <div class="analysis-card">
            <h4>Safe Inputs (Low)</h4>
            <div class="val" style="color: #55e6ff;">${low}</div>
        </div>
        <div class="analysis-card">
            <h4>Medium Warnings</h4>
            <div class="val" style="color: #ffd166;">${medium}</div>
        </div>
        <div class="analysis-card">
            <h4>High Vulnerabilities</h4>
            <div class="val" style="color: #ff6b81;">${high}</div>
        </div>
    `;

    summaryContainer.append(postureBox, grid);
}

/**
 * Load test history from /api/results into the reports table.
 */
async function loadReports() {
    const tableBody = document.getElementById("reportRows");
    if (!tableBody) return;

    tableBody.innerHTML = `<tr><td colspan="6" class="text-center">Loading reports from database...</td></tr>`;

    try {
        const response = await fetch("/api/results");
        if (!response.ok) throw new Error("Failed to fetch test records.");

        const results = await response.json();
        tableBody.replaceChildren();

        if (!Array.isArray(results) || results.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.className = "text-center";
            cell.textContent = "No tests have been performed yet. Run an SQL or XSS test to see results here.";
            row.appendChild(cell);
            tableBody.appendChild(row);
            return;
        }

        results.forEach(item => {
            const row = document.createElement("tr");

            // ID
            const idCell = document.createElement("td");
            idCell.textContent = item.id;
            row.appendChild(idCell);

            // Type
            const typeCell = document.createElement("td");
            const typeBadge = document.createElement("span");
            typeBadge.className = item.test_type === "SQL" ? "badge badge-low" : "badge badge-medium";
            typeBadge.textContent = item.test_type;
            typeCell.appendChild(typeBadge);
            row.appendChild(typeCell);

            // Tested Input
            const inputCell = document.createElement("td");
            const codeSpan = document.createElement("span");
            codeSpan.className = "code-cell";
            codeSpan.textContent = item.test_input;
            codeSpan.title = item.test_input;
            inputCell.appendChild(codeSpan);
            row.appendChild(inputCell);

            // Status
            const statusCell = document.createElement("td");
            statusCell.textContent = item.status;
            row.appendChild(statusCell);

            // Risk Badge
            const riskCell = document.createElement("td");
            const risk = item.risk || "Low";
            const riskBadge = document.createElement("span");
            riskBadge.className = `badge ${risk === "High" ? "badge-high" : (risk === "Medium" ? "badge-medium" : "badge-low")}`;
            riskBadge.textContent = risk;
            riskCell.appendChild(riskBadge);
            row.appendChild(riskCell);

            // Date
            const dateCell = document.createElement("td");
            dateCell.textContent = item.created_at;
            row.appendChild(dateCell);

            tableBody.appendChild(row);
        });

    } catch (error) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center risk-high">Unable to load reports: ${escapeHtml(error.message)}</td></tr>`;
        console.error("Reports loading error:", error);
    }
}

/**
 * Triggers CSV report download from Flask backend.
 */
function downloadReport() {
    window.location.href = "/api/report.csv";
}

/**
 * Clears test history in SQLite database with confirmation.
 */
async function clearHistory() {
    if (!confirm("Are you sure you want to clear all test history from the database?")) {
        return;
    }

    try {
        const response = await fetch("/api/clear", {
            method: "POST"
        });

        if (!response.ok) throw new Error("Failed to clear database.");

        await loadReports();
        await refreshData();
        alert("Test history cleared successfully.");
    } catch (error) {
        alert("Error clearing history: " + error.message);
    }
}

/**
 * Safe HTML string escaping for XSS prevention when rendering untrusted content.
 */
function escapeHtml(str) {
    if (typeof str !== "string") return str || "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Application initialization on DOM ready.
 */
document.addEventListener("DOMContentLoaded", function () {
    console.log("SecureGuard ready. Setting up routes and event handlers.");

    // Hash-based routing on initial page load
    const currentHash = window.location.hash.replace("#", "").trim();
    if (currentHash) {
        showModule(currentHash, false);
    } else {
        showModule("home", false);
    }

    // Handle browser back and forward button navigation
    window.addEventListener("hashchange", function () {
        const hash = window.location.hash.replace("#", "").trim() || "home";
        showModule(hash, false);
    });

    // Initial statistics fetch
    refreshData();
});
