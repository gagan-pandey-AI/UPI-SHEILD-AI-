// ==========================================
// UPI Shield AI
// Version 15
// Premium AI Scanner
// Part 1
// ==========================================

// Elements

const smsBox = document.getElementById("smsBox");

const analysisForm = document.getElementById("analysisForm");

const analyzeButton = document.getElementById("analyzeButton");

const analyzeButtonLabel = analyzeButton.textContent.trim();

const resultBox = document.getElementById("result");

const riskValue = document.getElementById("riskValue");

const actionButtons = document.getElementById("actionButtons");

const recommendationBox = document.getElementById("recommendationBox");

const recommendations = document.getElementById("recommendations");

function escapeHtml(value){
    return String(value ?? "").replace(/[&<>\"']/g, character => ({
        "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"
    })[character]);
}

function showToast(message, kind="info"){
    const region = document.getElementById("toastRegion");
    if(!region) return;
    region.replaceChildren();
    const toast = document.createElement("div");
    toast.className = `toast toast-${kind}`;
    toast.textContent = message;
    region.appendChild(toast);
    window.setTimeout(() => toast.remove(), 4500);
}

function formatReputation(item){
    const levels = new Set(["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]);
    const level = levels.has(item.risk_level) ? item.risk_level : "UNKNOWN";
    const reason = escapeHtml(item.detection_reason || "Reputation was not confirmed.");
    const providerName = String(item.provider || "").toLowerCase();
    const provider = providerName ? ` (${escapeHtml(providerName.replace(/_/g, " "))})` : "";
    const attribution = level === "MALICIOUS" && providerName.includes("google")
        ? ` <small>Advisory provided by Google. <a href="https://transparencyreport.google.com/safe-browsing/search" target="_blank" rel="noopener noreferrer">Review the Safe Browsing Advisory</a>.</small>`
        : "";
    return `Reputation: ${level}${provider} - ${reason}${attribution}`;
}

function formatUrlAnalysis(data){
    const urls = Array.isArray(data.urls) ? data.urls : [];
    if(!urls.length) return "";
    const details = urls.map(item => {
        const host = escapeHtml(item.host || "Unparsed URL");
        const indicators = Array.isArray(item.indicators) ? item.indicators : [];
        const summary = indicators.length
            ? indicators.map(indicator => escapeHtml(indicator.reason)).join("; ")
            : "No structural warning found.";
        return `${host} — ${summary}. ${formatReputation(item)}`;
    });
    return `<br><br><b>URL structure and reputation:</b><br>${details.join("<br>")}`;
}

function formatCategories(data){
    const categories = Array.isArray(data.all_categories) ? data.all_categories : [data.category];
    return categories.filter(Boolean).map(escapeHtml).join(", ");
}

function recommendationList(data){
    const items = Array.isArray(data.safety_recommendations) ? data.safety_recommendations : [];
    if(!items.length) return "<li>Verify unexpected payment and account requests independently.</li>";
    return items.map(item => `<li>${escapeHtml(item)}</li>`).join("");
}

function assessmentTitle(status, maliciousUrl=false){
    if(maliciousUrl) return "Potentially unsafe URL reported";
    if(status === "FRAUD") return "High-risk heuristic assessment";
    if(status === "SUSPICIOUS") return "Caution: heuristic indicators matched";
    if(status === "UNKNOWN" || status === "NO_TEXT_DETECTED") return "Assessment unavailable";
    return "No major patterns matched";
}

function formatWhyAssessment(data){
    const indicators = Array.isArray(data.observed_indicators) ? data.observed_indicators : [];
    const scoring = data.scoring && typeof data.scoring === "object" ? data.scoring : {};
    const sourceLabels = {
        message_pattern: "Message text pattern",
        url_structure: "URL structure",
        url_observation: "URL observation"
    };
    const entries = indicators.map(indicator => {
        const source = sourceLabels[indicator.source] || "Heuristic indicator";
        const points = Number.isFinite(Number(indicator.points)) ? Number(indicator.points) : 0;
        const host = indicator.host ? ` (${escapeHtml(indicator.host)})` : "";
        return `<li><span>${escapeHtml(indicator.reason || "Indicator matched")}${host}</span> <small>${escapeHtml(source)} - +${points} points</small></li>`;
    });
    let explanation;
    if(entries.length){
        explanation = `<ul class="explanation-list">${entries.join("")}</ul>`;
    }else if(data.evidence_status === "insufficient_ocr_text"){
        explanation = "OCR did not extract readable text, so there was no text evidence to assess. The image is not verified safe.";
    }else if(data.evidence_status === "insufficient_text"){
        explanation = "There was not enough readable text to assess.";
    }else{
        explanation = "No major scam patterns matched these rules. That does not prove the message is safe.";
    }
    const rawPoints = Number.isFinite(Number(scoring.raw_points)) ? Number(scoring.raw_points) : 0;
    const riskScore = Number.isFinite(Number(data.risk_score)) ? Number(data.risk_score) : 0;
    const scoreSummary = scoring.cap_applied
        ? `Unique heuristic weights total ${rawPoints}; the displayed score is capped at ${escapeHtml(scoring.score_cap || 100)}.`
        : `Observed indicators contribute ${rawPoints} heuristic points to the displayed score of ${riskScore}/100.`;
    const limitations = Array.isArray(data.analysis_limitations) ? data.analysis_limitations : [];
    const limitationItems = limitations.length
        ? `<ul class="explanation-list">${limitations.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
        : `<p class="explanation-limit">URL reputation is time-sensitive; unchecked URLs remain UNKNOWN.</p>`;
    return `<section class="analysis-explanation" aria-label="Assessment explanation"><h3>Why this assessment?</h3>${explanation}<p class="explanation-score">${scoreSummary}</p><p class="explanation-limit">Risk points are heuristic weights, not probabilities. No-match reputation results do not guarantee safety.</p>${limitationItems}</section>`;
}

// ==========================================
// Risk Meter Animation
// ==========================================

function animateRisk(score){

    let current = 0;

    riskValue.textContent = "0/100";

    let timer = setInterval(function(){

        current++;

        riskValue.textContent = current + "/100";

        if(current >= score){

            clearInterval(timer);

        }

    },15);

}

// ==========================================
// AI Loading Animation
// ==========================================

let scanPending = false;

async function loadingAnimation(){
    resultBox.className = "result loading";
    resultBox.setAttribute("aria-busy", "true");
    resultBox.innerHTML = '<span class="loading-spinner" aria-hidden="true"></span>Checking message patterns and URL structure locally...';
}

// ==========================================
// Main AI Function
// ==========================================

async function checkFraud(){

    if(scanPending) return;

    actionButtons.style.display="none";

    recommendationBox.style.display="none";

    let sms=smsBox.value.trim();

    if(sms===""){

        resultBox.className="result error";
        resultBox.textContent="Please enter or paste a message.";
        smsBox.focus();
        return;

    }

    scanPending = true;
    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyzing...";

    try{
        await loadingAnimation();

        const response=await fetch("/check",{

            method:"POST",

            headers:{

                "Content-Type":"application/json",
                "X-CSRFToken":document.querySelector('meta[name="csrf-token"]').content

            },

            body:JSON.stringify({

                message:sms

            })

        });

        const data=await response.json();

        if(!response.ok){
            resultBox.className="result error fade-in";
            resultBox.removeAttribute("aria-busy");
            resultBox.textContent=data.error || "The scan could not be completed.";
            animateRisk(0);
            return;
        }

        animateRisk(data.risk_score);

        // Result Part







        if(data.url_reputation_alert){

            actionButtons.style.display="flex";
            recommendationBox.style.display="block";
            resultBox.className="result fraud fade-in";
            resultBox.innerHTML=`
                <h2>Potentially unsafe URL reported</h2>
                <p>${escapeHtml(data.url_reputation_alert.message || "A reputation provider reported a known threat. Do not open this link.")}</p>
                <b>Heuristic Risk Score:</b> ${escapeHtml(data.risk_score)}/100 (not a probability)
                <br><b>Risk level:</b> ${escapeHtml(data.risk_level || "UNKNOWN")}
                <br><br>
                <b>Categories:</b> ${formatCategories(data)}
                ${formatWhyAssessment(data)}
                ${formatUrlAnalysis(data)}
            `;
            recommendations.innerHTML=`
                <ul style="text-align:left;line-height:2;">
                    <li>Do not open the reported URL or enter any information there.</li>
                    <li>Verify the sender through a contact method you already trust.</li>
                    <li>If you shared payment details, contact your bank promptly.</li>
                </ul>
            `;

        }

        else if(data.status==="FRAUD"){

            actionButtons.style.display="flex";

            recommendationBox.style.display="block";

            resultBox.className="result fraud fade-in";

            resultBox.innerHTML=`

                <h2>High-risk heuristic assessment</h2>

                <br>

                <b>Risk Score :</b> ${escapeHtml(data.risk_score)}/100
                <br><b>Risk level:</b> ${escapeHtml(data.risk_level || "UNKNOWN")}

                <br><br>

                <b>Assessment :</b> ${escapeHtml(data.confidence_label || data.confidence)}

                <br><br>

                <b>Categories :</b> ${formatCategories(data)}

                <br><br>

                ${formatWhyAssessment(data)}
                ${formatUrlAnalysis(data)}

            `;

            recommendations.innerHTML=`

            <ul style="text-align:left;line-height:2;">

                <li>❌ Never share OTP.</li>

                <li>❌ Don't click suspicious links.</li>

                <li>🏦 Contact your bank immediately.</li>

                <li>🚨 Report on cybercrime.gov.in</li>

                <li>📞 Call 1930 if money is involved.</li>

            </ul>

            `;

        }

        else if(data.status==="SUSPICIOUS"){

            actionButtons.style.display="flex";

            recommendationBox.style.display="block";

            resultBox.className="result suspicious fade-in";

            resultBox.innerHTML=`

                <h2>⚠️ SUSPICIOUS MESSAGE</h2>

                <br>

                <b>Risk Score :</b> ${escapeHtml(data.risk_score)}/100
                <br><b>Risk level:</b> ${escapeHtml(data.risk_level || "UNKNOWN")}

                <br><br>

                <b>Assessment :</b> ${escapeHtml(data.confidence_label || data.confidence)}

                <br><br>

                <b>Categories :</b> ${formatCategories(data)}

                <br><br>

                ${formatWhyAssessment(data)}
                ${formatUrlAnalysis(data)}

            `;

            recommendations.innerHTML=`

            <ul style="text-align:left;line-height:2;">

                <li>🔍 Verify the sender.</li>

                <li>🌐 Visit only the official website.</li>

                <li>⚠️ Don't share banking details.</li>

                <li>🛡️ Ignore unknown payment requests.</li>

            </ul>

            `;

        }

        else if(data.status==="UNKNOWN" || data.status==="NO_TEXT_DETECTED"){
            recommendationBox.style.display="block";
            resultBox.className="result error fade-in";
            resultBox.innerHTML=`
                <h2>Assessment unavailable</h2>
                <p>${escapeHtml(data.detection_reason || data.reasons?.[0] || "There was not enough readable text to assess.")}</p>
                <b>Risk level:</b> UNKNOWN
                ${formatWhyAssessment(data)}
            `;
        }

        else{

            recommendationBox.style.display="block";

            resultBox.className="result safe fade-in";

            resultBox.innerHTML=`

                <h2>No major patterns matched</h2>

                <br>

                <b>Risk Score :</b> ${escapeHtml(data.risk_score)}/100
                <br><b>Risk level:</b> ${escapeHtml(data.risk_level || "UNKNOWN")}

                <br><br>

                <b>Assessment :</b> ${escapeHtml(data.confidence_label || data.confidence)}

                <br><br>

                ${formatWhyAssessment(data)}
                ${formatUrlAnalysis(data)}

            `;

            recommendations.innerHTML=`

            <ul style="text-align:left;line-height:2;">

                <li>No major heuristic indicators matched; verify requests independently.</li>

                <li>✅ Stay alert while making payments.</li>

                <li>🛡️ Keep your banking apps updated.</li>

            </ul>

            `;

        }

        recommendations.innerHTML = `<ul class="safety-action-list">${recommendationList(data)}</ul>`;
        resultBox.removeAttribute("aria-busy");

    }

    catch(error){

        resultBox.className="result error";
        resultBox.removeAttribute("aria-busy");

        resultBox.innerHTML=`

            ❌ Connection Error

            <br><br>

            The local pattern analysis could not be completed.

        `;

    }

    finally{
        scanPending = false;
        analyzeButton.disabled = false;
        analyzeButton.textContent = analyzeButtonLabel;
    }

}

async function scanImage(){
    const picker = document.getElementById("imageFile");
    const output = document.getElementById("imageScanResult");
    const review = document.getElementById("imageReview");
    const scanButton = document.getElementById("imageScanButton");
    const file = picker.files && picker.files[0];
    review.hidden = true;
    if(!file){ output.textContent = "Choose a PNG or JPEG image first."; return; }
    if(!["image/png", "image/jpeg"].includes(file.type)){ output.textContent = "Only PNG and JPEG images are supported."; return; }
    if(file.size > 4 * 1024 * 1024){ output.textContent = "The image must be 4 MB or smaller."; return; }
    output.textContent = "Extracting readable text and QR content locally. This may take a few seconds.";
    output.setAttribute("aria-busy", "true");
    scanButton.disabled = true;
    const form = new FormData();
    form.append("image", file);
    try{
        const response = await fetch("/extract-image", {
            method: "POST",
            headers: {"X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content},
            body: form
        });
        const data = await response.json();
        if(!response.ok){ output.textContent = data.error || "Image scan could not be completed."; return; }
        document.getElementById("extractedImageText").value = data.extracted_text || "";
        review.hidden = !data.extracted_text;
        window.lastQrAnalysis = data.qr_analysis;
        output.innerHTML = formatQrAnalysis(data.qr_analysis);
        if(!data.extracted_text) output.innerHTML += "<p>No readable text was detected. This does not mean the image is safe.</p>";
        showToast("Image text and QR content were extracted locally. Review the findings before acting.", "success");
    }catch(error){
        output.textContent = "Image scan could not be completed. Please try again.";
        showToast("Image scan could not be completed.", "error");
    }finally{
        output.removeAttribute("aria-busy");
        scanButton.disabled = false;
    }
}

function formatQrAnalysis(analysis){
    if(!analysis || typeof analysis !== "object") return "";
    const codes = Array.isArray(analysis.codes) ? analysis.codes : [];
    const rendered = codes.map((code, index) => {
        const urls = Array.isArray(code.urls) ? code.urls : [];
        const urlLines = urls.map(item => {
            const host = escapeHtml(item.host || "Unparsed URL");
            const warnings = Array.isArray(item.indicators) ? item.indicators : [];
            const detail = warnings.length ? warnings.map(warning => escapeHtml(warning.reason)).join("; ") : "No structural warning found.";
            return `<li>${host}: ${detail}. ${formatReputation(item)}</li>`;
        }).join("");
        const urlsHtml = urlLines ? `<p>URL structure findings:</p><ul>${urlLines}</ul>` : "<p>No web URL was identified in this QR content.</p>";
        const indicators = Array.isArray(code.identified_indicators) ? code.identified_indicators : [];
        const indicatorHtml = indicators.length
            ? `<ul class="explanation-list">${indicators.map(item => `<li>${escapeHtml(item.reason || item.code)}</li>`).join("")}</ul>`
            : "";
        return `<article class="qr-result"><h4>QR code ${index + 1} (${escapeHtml(code.content_type || "content")})</h4><p><b>Risk level:</b> ${escapeHtml(code.risk_level || "UNKNOWN")}</p><p>${escapeHtml(code.detection_reason || "QR content was decoded locally.")}</p>${indicatorHtml}<pre>${escapeHtml(code.content || "")}</pre>${urlsHtml}<p>${escapeHtml(code.recommended_action || "Review content before acting.")}</p><small>${escapeHtml(code.warning || "Decoded content is not verified safe.")}</small></article>`;
    }).join("");
    const reputationNote = analysis.reputation_checked
        ? "A provider checked the identified URL. A no-match does not guarantee safety."
        : "URL reputation could not be confirmed. No QR URL was opened and no payment was made.";
    const limitations = Array.isArray(analysis.analysis_limitations) ? analysis.analysis_limitations : [];
    const limitsHtml = limitations.map(item => `<li>${escapeHtml(item)}</li>`).join("");
    return `<section class="analysis-explanation" aria-label="QR code analysis"><h3>QR code safety - ${escapeHtml(analysis.risk_level || "UNKNOWN")}</h3><p>${escapeHtml(analysis.detection_reason || analysis.message || "QR decoding does not verify safety.")}</p>${rendered}<p><b>Safer next step:</b> ${escapeHtml(analysis.recommended_action || "Review the content before acting.")}</p><p class="explanation-limit">${reputationNote}</p>${limitsHtml ? `<ul class="explanation-list">${limitsHtml}</ul>` : ""}</section>`;
}

function formatSafetyRecommendations(data){
    const items = Array.isArray(data.safety_recommendations) ? data.safety_recommendations : [];
    if(!items.length) return "";
    return `<section class="analysis-explanation" aria-label="Safety recommendations"><h3>Safer next steps</h3><ul class="explanation-list">${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>`;
}

async function analyzeImageText(){
    const output = document.getElementById("imageScanResult");
    const text = document.getElementById("extractedImageText").value;
    const button = document.getElementById("analyzeImageTextButton");
    if(!text.trim()){ output.textContent = "There is no extracted text to analyze. The image is not verified safe."; return; }
    output.setAttribute("aria-busy", "true");
    button.disabled = true;
    output.textContent = "Applying the existing scam-pattern and URL-structure rules...";
    try{
        const response = await fetch("/analyze-extracted-image", {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content},
            body: JSON.stringify({text})
        });
        const data = await response.json();
        if(!response.ok){ output.textContent = data.error || "Analysis could not be completed."; return; }
        output.innerHTML = `
            ${formatQrAnalysis(window.lastQrAnalysis)}
            <h3>${escapeHtml(assessmentTitle(data.status, Boolean(data.url_reputation_alert)))}</h3>
            <p><b>Heuristic score:</b> ${escapeHtml(data.risk_score)}/100 (not a probability)</p>
            <p><b>Categories:</b> ${formatCategories(data)}</p>
            <p><b>Assessment:</b> ${escapeHtml(data.confidence_label || data.confidence)}</p>
            ${formatWhyAssessment(data)}
            ${formatUrlAnalysis(data)}
            ${formatSafetyRecommendations(data)}
            <h3>Reviewed text sent for analysis</h3>
            <pre>${escapeHtml(data.extracted_text || "")}</pre>
            <small>Text rules cannot verify payment receipts, logos, or image authenticity. Extracted URLs were not opened.</small>
        `;
    }catch(error){
        output.textContent = "Analysis could not be completed. Please try again.";
    }finally{
        output.removeAttribute("aria-busy");
        button.disabled = false;
    }
}
// ==========================================
// UPI Shield AI
// Version 15
// Premium AI Scanner
// Part 3 (Final)
// ==========================================

// Clipboard Paste

async function pasteClipboard(){

    try{

        const text=await navigator.clipboard.readText();

        smsBox.value=text;

        resultBox.className="result fade-in";

        resultBox.innerHTML="📋 Message pasted successfully.";

        recommendationBox.style.display="none";

        actionButtons.style.display="none";

        animateRisk(0);
        showToast("Message pasted. Review it before analysis.", "success");

    }

    catch(error){

        showToast("Clipboard permission was denied. Paste the message into the text box.", "error");

    }

}
// ==========================================
// Reset Screen while Typing
// ==========================================

smsBox.addEventListener("input",function(){

    resultBox.className="result";

    resultBox.innerHTML="Local pattern checker ready...";

    recommendationBox.style.display="none";

    actionButtons.style.display="none";

    animateRisk(0);

});

// ==========================================
// Enter Key Support
// Ctrl + Enter = Analyze
// ==========================================

analysisForm.addEventListener("submit",function(event){
    event.preventDefault();
    checkFraud();
});

smsBox.addEventListener("keydown",function(event){

    if(event.ctrlKey && event.key==="Enter"){

        event.preventDefault();
        if(typeof analysisForm.requestSubmit === "function"){
            analysisForm.requestSubmit(analyzeButton);
        }else{
            analysisForm.dispatchEvent(new Event("submit", {bubbles:true, cancelable:true}));
        }

    }

});

document.getElementById("pasteButton").addEventListener("click", pasteClipboard);

document.getElementById("imageScanButton").addEventListener("click", scanImage);

document.getElementById("analyzeImageTextButton").addEventListener("click", analyzeImageText);

// ==========================================
// Welcome Message
// ==========================================

window.onload=function(){

    resultBox.className="result fade-in";

    resultBox.innerHTML=`

        🛡️ Welcome to UPI Shield AI

        <br><br>

        Paste any SMS, UPI message or suspicious text.

        <br><br>

        Press <b>Ctrl + Enter</b> or click
        <b>Analyze Message</b>.

    `;

    animateRisk(0);

};

// ==========================================
// End of Script
// ==========================================
