async function checkFraud() {

    let actionButtons = document.getElementById("actionButtons");
    actionButtons.style.display = "none";

    let sms = document.getElementById("smsBox").value;

    let resultBox = document.getElementById("result");

    const response = await fetch("/check", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            message: sms
        })
    });

    const data = await response.json();

    if (data.status === "FRAUD") {

        actionButtons.style.display = "block";

        resultBox.className = "result fraud";

        resultBox.innerHTML = `
        🚨 FRAUD DETECTED <br><br>
        Risk Score: ${data.risk_score}/100 <br><br>
        ${data.reasons.join("<br>")}
        `;

    } else if (data.status === "SUSPICIOUS") {

        resultBox.className = "result suspicious";

        resultBox.innerHTML = `
        ⚠️ SUSPICIOUS MESSAGE <br><br>
        Risk Score: ${data.risk_score}/100 <br><br>
        ${data.reasons.join("<br>")}
        `;

    } else {

        resultBox.className = "result safe";

        resultBox.innerHTML = `
        ✅ SAFE MESSAGE <br><br>
        Risk Score: ${data.risk_score}/100
        `;
    }
}

async function pasteClipboard() {

    try {

        const text = await navigator.clipboard.readText();

        document.getElementById("smsBox").value = text;

    } catch (error) {

        alert("Clipboard access denied.");

    }
}


