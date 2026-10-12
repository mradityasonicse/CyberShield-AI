/**
 * CyberShield AI - Core Application Orchestrator
 * Connects UI interactions, PII scanning, Gemini analysis, and dashboard rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Application State
  const state = {
    currentLanguage: "en",
    currentTab: "tab-analyzer",
    activeInputMode: "text",
    uploadedImageFile: null,
    latestReportData: null,
    sampleCases: [],
    customApiKey: "",
    piiDebounceTimer: null
  };

  // DOM Elements
  const el = {
    // Navigation
    navBtns: document.querySelectorAll(".nav-btn"),
    tabPanes: document.querySelectorAll(".tab-pane"),
    langBtns: document.querySelectorAll(".lang-btn"),
    engineBadge: document.getElementById("engineStatusBadge"),
    engineLabel: document.getElementById("engineStatusLabel"),
    
    // Inputs & Console
    cTabBtns: document.querySelectorAll(".c-tab-btn"),
    textInputPanel: document.getElementById("textInputContainer"),
    imageInputPanel: document.getElementById("imageInputContainer"),
    suspiciousInput: document.getElementById("suspiciousInput"),
    charCount: document.getElementById("charCount"),
    wordCount: document.getElementById("wordCount"),
    clearInputBtn: document.getElementById("clearInputBtn"),
    
    // Image Upload
    imageDropZone: document.getElementById("imageDropZone"),
    screenshotFileInput: document.getElementById("screenshotFileInput"),
    dropZoneIdle: document.getElementById("dropZoneIdle"),
    dropZonePreview: document.getElementById("dropZonePreview"),
    previewImage: document.getElementById("previewImage"),
    previewFilename: document.getElementById("previewFilename"),
    removeImageBtn: document.getElementById("removeImageBtn"),
    imageCompanionText: document.getElementById("imageCompanionText"),
    
    // PII Shield
    piiBanner: document.getElementById("piiWarningBanner"),
    piiMessage: document.getElementById("piiDetectedMessage"),
    autoRedactToggle: document.getElementById("autoRedactToggle"),
    
    // Samples
    samplePillsList: document.getElementById("samplePillsList"),
    
    // Actions & Buttons
    analyzeBtn: document.getElementById("analyzeBtn"),
    btnLoader: document.querySelector(".btn-loader"),
    btnText: document.querySelector(".btn-text"),
    
    // Results Elements
    resultsSection: document.getElementById("resultsSection"),
    riskCard: document.getElementById("riskCard"),
    riskBadge: document.getElementById("riskBadge"),
    threatCategory: document.getElementById("threatCategory"),
    riskScoreValue: document.getElementById("riskScoreValue"),
    scoreCirclePath: document.getElementById("scoreCirclePath"),
    confidenceValue: document.getElementById("confidenceValue"),
    engineUsedLabel: document.getElementById("engineUsedLabel"),
    privacyStatusLabel: document.getElementById("privacyStatusLabel"),
    analyzedTimestamp: document.getElementById("analyzedTimestamp"),
    
    // Summary
    englishSummaryBlock: document.getElementById("englishSummaryBlock"),
    hinglishSummaryBlock: document.getElementById("hinglishSummaryBlock"),
    btnShowEnSummary: document.getElementById("btnShowEnSummary"),
    btnShowHiSummary: document.getElementById("btnShowHiSummary"),
    
    // Warnings & Findings
    warningSignsList: document.getElementById("warningSignsList"),
    warningCountBadge: document.getElementById("warningCountBadge"),
    urlAnalysisCard: document.getElementById("urlAnalysisCard"),
    urlFindingsBody: document.getElementById("urlFindingsBody"),
    recommendedActionsList: document.getElementById("recommendedActionsList"),
    
    // Tutor Card
    tutorTopicTitle: document.getElementById("tutorTopicTitle"),
    tutorTakeawayEn: document.getElementById("tutorTakeawayEn"),
    tutorTakeawayHi: document.getElementById("tutorTakeawayHi"),
    
    // Export Buttons
    btnCopyReport: document.getElementById("btnCopyReport"),
    btnDownloadJson: document.getElementById("btnDownloadJson"),
    btnPrintReport: document.getElementById("btnPrintReport"),
    
    // Settings Modal
    openSettingsBtn: document.getElementById("openSettingsBtn"),
    closeSettingsBtn: document.getElementById("closeSettingsBtn"),
    settingsModal: document.getElementById("settingsModal"),
    geminiApiKeyInput: document.getElementById("geminiApiKeyInput"),
    toggleKeyVisibilityBtn: document.getElementById("toggleKeyVisibilityBtn"),
    geminiModelSelect: document.getElementById("geminiModelSelect"),
    saveApiKeyBtn: document.getElementById("saveApiKeyBtn"),
    clearApiKeyBtn: document.getElementById("clearApiKeyBtn"),
    settingsAlertBox: document.getElementById("settingsAlertBox"),
    
    // Toast Container
    toastContainer: document.getElementById("toastContainer")
  };

  // Toast Utility
  window.showToast = function(message, type = "info") {
    if (!el.toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    let icon = "fa-circle-info";
    if (type === "success") icon = "fa-circle-check";
    if (type === "warning") icon = "fa-triangle-exclamation";
    
    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
    el.toastContainer.appendChild(toast);
    
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      setTimeout(() => toast.remove(), 300);
    }, 3800);
  };

  // Initialize App
  function init() {
    setupTabNavigation();
    setupLanguageSwitcher();
    setupConsoleInputs();
    setupImageUpload();
    setupSettingsModal();
    setupExportHandlers();
    loadSampleCases();
    checkEngineHealth();

    // Initialize standalone quiz
    if (window.cyberQuiz) {
      window.cyberQuiz.initStandaloneQuiz();
    }
  }

  // 1. Navigation Tabs
  function setupTabNavigation() {
    el.navBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        const targetTabId = btn.dataset.tab;
        
        el.navBtns.forEach(b => b.classList.remove("active"));
        el.tabPanes.forEach(p => p.classList.remove("active"));
        
        btn.classList.add("active");
        const targetPane = document.getElementById(targetTabId);
        if (targetPane) targetPane.classList.add("active");
        state.currentTab = targetTabId;
      });
    });
  }

  // 2. Language Switcher
  function setupLanguageSwitcher() {
    el.langBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        el.langBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        state.currentLanguage = btn.dataset.lang;
        updateLanguageDisplay();
      });
    });

    if (el.btnShowEnSummary && el.btnShowHiSummary) {
      el.btnShowEnSummary.onclick = () => {
        el.btnShowEnSummary.classList.add("active");
        el.btnShowHiSummary.classList.remove("active");
        el.englishSummaryBlock.classList.add("active");
        el.hinglishSummaryBlock.classList.remove("active");
      };

      el.btnShowHiSummary.onclick = () => {
        el.btnShowHiSummary.classList.add("active");
        el.btnShowEnSummary.classList.remove("active");
        el.hinglishSummaryBlock.classList.add("active");
        el.englishSummaryBlock.classList.remove("active");
      };
    }
  }

  function updateLanguageDisplay() {
    if (state.currentLanguage === "hi") {
      if (el.btnShowHiSummary) el.btnShowHiSummary.click();
    } else {
      if (el.btnShowEnSummary) el.btnShowEnSummary.click();
    }
  }

  // 3. Console Inputs & Word Counters
  function setupConsoleInputs() {
    // Mode toggling (Text vs Image)
    el.cTabBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        el.cTabBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        
        const mode = btn.dataset.inputMode;
        state.activeInputMode = mode;
        
        if (mode === "text") {
          el.textInputPanel.classList.add("active");
          el.imageInputPanel.classList.remove("active");
        } else {
          el.textInputPanel.classList.remove("active");
          el.imageInputPanel.classList.add("active");
        }
      });
    });

    // Real-time Text metrics & PII checking
    el.suspiciousInput.addEventListener("input", () => {
      const text = el.suspiciousInput.value;
      el.charCount.textContent = `${text.length} characters`;
      
      const words = text.trim() ? text.trim().split(/\s+/).length : 0;
      el.wordCount.textContent = `${words} words`;

      // Debounced PII live scan
      clearTimeout(state.piiDebounceTimer);
      state.piiDebounceTimer = setTimeout(() => {
        scanInputForPii(text);
      }, 400);
    });

    el.clearInputBtn.onclick = () => {
      el.suspiciousInput.value = "";
      el.charCount.textContent = "0 characters";
      el.wordCount.textContent = "0 words";
      el.piiBanner.classList.add("hidden");
    };

    el.analyzeBtn.onclick = handleAnalyzeThreat;
  }

  // Live PII Detection
  async function scanInputForPii(text) {
    if (!text || text.trim().length < 5) {
      el.piiBanner.classList.add("hidden");
      return;
    }

    try {
      const res = await fetch("/api/scan-pii", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });
      const data = await res.json();
      
      if (data.has_sensitive_data) {
        const labels = data.findings.map(f => f.label).join(", ");
        el.piiMessage.textContent = `Found potential ${labels}.`;
        el.piiBanner.classList.remove("hidden");
      } else {
        el.piiBanner.classList.add("hidden");
      }
    } catch (err) {
      console.warn("PII scan check failed", err);
    }
  }

  // 4. Image Upload & Multimodal Handling
  function setupImageUpload() {
    el.dropZoneIdle.onclick = () => el.screenshotFileInput.click();

    el.screenshotFileInput.onchange = (e) => {
      const file = e.target.files[0];
      if (file) handleImageSelected(file);
    };

    el.imageDropZone.ondragover = (e) => {
      e.preventDefault();
      el.imageDropZone.classList.add("dragover");
    };

    el.imageDropZone.ondragleave = () => {
      el.imageDropZone.classList.remove("dragover");
    };

    el.imageDropZone.ondrop = (e) => {
      e.preventDefault();
      el.imageDropZone.classList.remove("dragover");
      if (e.dataTransfer.files.length) {
        handleImageSelected(e.dataTransfer.files[0]);
      }
    };

    el.removeImageBtn.onclick = () => {
      state.uploadedImageFile = null;
      el.screenshotFileInput.value = "";
      el.dropZonePreview.classList.add("hidden");
      el.dropZoneIdle.classList.remove("hidden");
    };
  }

  function handleImageSelected(file) {
    if (!file.type.startsWith("image/")) {
      window.showToast("Please upload a valid image (PNG, JPG, WEBP)", "warning");
      return;
    }
    if (file.size > 16 * 1024 * 1024) {
      window.showToast("Image size exceeds 16MB limit", "warning");
      return;
    }

    state.uploadedImageFile = file;
    el.previewFilename.textContent = file.name;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      el.previewImage.src = e.target.result;
      el.dropZoneIdle.classList.add("hidden");
      el.dropZonePreview.classList.remove("hidden");
    };
    reader.readAsDataURL(file);
  }

  // 5. Sample Cases Loader
  async function loadSampleCases() {
    try {
      const res = await fetch("/api/samples");
      const json = await res.json();
      if (json.status === "success" && json.samples) {
        state.sampleCases = json.samples;
        renderSamplePills(json.samples);
      }
    } catch (err) {
      console.error("Failed to load sample cases", err);
    }
  }

  function renderSamplePills(samples) {
    if (!el.samplePillsList) return;
    el.samplePillsList.innerHTML = "";

    samples.forEach(sample => {
      const pill = document.createElement("button");
      pill.className = "sample-pill-btn";
      
      let icon = "fa-shield-halved";
      if (sample.id.includes("sms")) icon = "fa-comment-sms";
      if (sample.id.includes("email")) icon = "fa-envelope";
      if (sample.id.includes("url")) icon = "fa-link";
      if (sample.id.includes("whatsapp")) icon = "fa-gift";
      if (sample.id.includes("safe")) icon = "fa-circle-check";
      if (sample.id.includes("log")) icon = "fa-terminal";

      pill.innerHTML = `<i class="fa-solid ${icon}"></i> ${sample.title}`;
      pill.onclick = () => loadSampleIntoConsole(sample);
      el.samplePillsList.appendChild(pill);
    });
  }

  function loadSampleIntoConsole(sample) {
    // Switch to text mode if not active
    const textTabBtn = document.querySelector('.c-tab-btn[data-input-mode="text"]');
    if (textTabBtn) textTabBtn.click();

    el.suspiciousInput.value = sample.sample_text;
    el.suspiciousInput.dispatchEvent(new Event("input"));
    
    // Auto-scroll to console
    el.suspiciousInput.scrollIntoView({ behavior: "smooth", block: "center" });
    window.showToast(`Loaded: ${sample.title}`, "info");

    // Auto-trigger analysis for instant preview
    setTimeout(() => {
      handleAnalyzeThreat();
    }, 300);
  }

  // 6. Engine Health & Status Check
  async function checkEngineHealth() {
    try {
      const res = await fetch("/api/health");
      const data = await res.json();
      
      if (data.api_key_configured) {
        el.engineBadge.className = "engine-badge";
        el.engineLabel.textContent = `Gemini AI Active (${data.gemini_model})`;
      } else {
        el.engineBadge.className = "engine-badge fallback";
        el.engineLabel.textContent = "Offline Heuristic Mode (Click ⚙ to add API Key)";
      }
    } catch (err) {
      console.warn("Health check unreachable", err);
    }
  }

  // 7. Settings Modal
  function setupSettingsModal() {
    el.openSettingsBtn.onclick = () => {
      el.settingsAlertBox.className = "settings-alert hidden";
      el.settingsModal.classList.remove("hidden");
    };

    el.closeSettingsBtn.onclick = () => {
      el.settingsModal.classList.add("hidden");
    };

    el.toggleKeyVisibilityBtn.onclick = () => {
      const isPass = el.geminiApiKeyInput.type === "password";
      el.geminiApiKeyInput.type = isPass ? "text" : "password";
      el.toggleKeyVisibilityBtn.innerHTML = isPass ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
    };

    el.saveApiKeyBtn.onclick = async () => {
      const key = el.geminiApiKeyInput.value.trim();
      try {
        const res = await fetch("/api/set-key", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ api_key: key })
        });
        const d = await res.json();
        
        el.settingsAlertBox.className = "settings-alert success";
        el.settingsAlertBox.textContent = key ? "Gemini API Key saved for this session!" : "API Key cleared.";
        checkEngineHealth();
        setTimeout(() => el.settingsModal.classList.add("hidden"), 1000);
      } catch (err) {
        el.settingsAlertBox.className = "settings-alert error";
        el.settingsAlertBox.textContent = "Failed to update configuration.";
      }
    };

    el.clearApiKeyBtn.onclick = () => {
      el.geminiApiKeyInput.value = "";
      el.saveApiKeyBtn.click();
    };
  }

  // 8. Primary Threat Analysis Runner
  async function handleAnalyzeThreat() {
    const textInput = el.suspiciousInput.value.trim();
    const companionText = el.imageCompanionText.value.trim();
    const hasImage = !!state.uploadedImageFile;

    if (!textInput && !hasImage) {
      window.showToast("Please enter a suspicious message, URL, log, or upload a screenshot.", "warning");
      el.suspiciousInput.focus();
      return;
    }

    // Toggle Loading State
    el.analyzeBtn.disabled = true;
    el.btnText.classList.add("hidden");
    el.btnLoader.classList.remove("hidden");

    try {
      let response;
      const maskPii = el.autoRedactToggle.checked;

      if (hasImage) {
        const formData = new FormData();
        formData.append("image", state.uploadedImageFile);
        formData.append("text", textInput || companionText || "Please inspect this screenshot for phishing or scam threats.");
        formData.append("mask_pii", maskPii);
        
        response = await fetch("/api/analyze", {
          method: "POST",
          body: formData
        });
      } else {
        response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: textInput,
            mask_pii: maskPii
          })
        });
      }

      const result = await response.json();

      if (result.status === "success" && result.data) {
        state.latestReportData = result.data;
        renderThreatReport(result.data);
        window.showToast("Threat Analysis Complete!", "success");
      } else {
        window.showToast(result.message || "Threat analysis failed", "warning");
      }
    } catch (err) {
      console.error("Threat analysis request error:", err);
      window.showToast("Network error during threat analysis", "warning");
    } finally {
      el.analyzeBtn.disabled = false;
      el.btnText.classList.remove("hidden");
      el.btnLoader.classList.add("hidden");
    }
  }

  // 9. Dashboard Results Renderer
  function renderThreatReport(report) {
    el.resultsSection.classList.remove("hidden");

    // Risk Header
    const risk = report.overall_risk || "MEDIUM";
    el.riskBadge.textContent = `${risk} RISK`;
    el.riskCard.className = `result-header-card glass-panel ${risk}`;
    el.threatCategory.textContent = report.threat_category || "Social Engineering & Phishing";

    // Gauge Score & Stroke animation
    const score = report.risk_score || 50;
    el.riskScoreValue.textContent = `${score}%`;
    el.scoreCirclePath.setAttribute("stroke-dasharray", `${score}, 100`);

    // Confidence
    el.confidenceValue.textContent = `Confidence: ${report.confidence_percentage || 90}%`;

    // Metadata
    el.engineUsedLabel.textContent = report.engine_used || "Google Gemini 2.5 Flash";
    el.analyzedTimestamp.textContent = new Date().toLocaleTimeString();

    // Privacy Status
    if (report.privacy_audit && report.privacy_audit.redacted_items && report.privacy_audit.redacted_items.length > 0) {
      el.privacyStatusLabel.textContent = `Masked ${report.privacy_audit.redacted_items.join(", ")}`;
      el.privacyStatusLabel.className = "meta-val highlight-green";
    } else {
      el.privacyStatusLabel.textContent = "Verified Clean (No PII Detected)";
      el.privacyStatusLabel.className = "meta-val";
    }

    // Dual Summaries
    el.englishSummaryBlock.textContent = report.summary_en || "No summary provided.";
    el.hinglishSummaryBlock.textContent = report.summary_hi || "Koi Hinglish summary uplabdh nahi hai.";
    updateLanguageDisplay();

    // Warning Signs Grid
    renderWarningSigns(report.warning_signs || []);

    // URL Forensics
    renderUrlForensics(report.url_analysis);

    // Recommended Actions Playbook
    renderRecommendedActions(report.recommended_actions || []);

    // Cyber Tutor Pro-Tip Card
    if (report.cyber_tutor_tip) {
      el.tutorTopicTitle.textContent = report.cyber_tutor_tip.topic || "Zero Trust Verification";
      el.tutorTakeawayEn.textContent = report.cyber_tutor_tip.takeaway_en || "";
      el.tutorTakeawayHi.textContent = report.cyber_tutor_tip.takeaway_hi ? `Hinglish: ${report.cyber_tutor_tip.takeaway_hi}` : "";
    }

    // Dynamic Quiz Injection
    if (window.cyberQuiz && report.quiz && report.quiz.length) {
      window.cyberQuiz.renderDynamicQuiz(report.quiz);
    }

    // Smooth scroll down to results
    el.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderWarningSigns(signs) {
    el.warningCountBadge.textContent = `${signs.length} Red Flags`;
    el.warningSignsList.innerHTML = "";

    if (!signs.length) {
      el.warningSignsList.innerHTML = `
        <div class="warning-card">
          <div class="warning-card-head">
            <span class="warning-card-title">Clean Communication</span>
            <span class="severity-pill LOW">SAFE</span>
          </div>
          <p class="warning-exp-en">No immediate phishing, artificial urgency, or credential theft indicators detected.</p>
        </div>
      `;
      return;
    }

    signs.forEach(sign => {
      const card = document.createElement("div");
      card.className = "warning-card";

      const severity = sign.severity || "HIGH";
      card.innerHTML = `
        <div class="warning-card-head">
          <span class="warning-card-title">${sign.title || 'Suspicious Indicator'}</span>
          <span class="severity-pill ${severity}">${severity}</span>
        </div>
        ${sign.quote ? `<div class="warning-quote">"${sign.quote}"</div>` : ''}
        <div class="warning-exp-en"><strong>Why Dangerous:</strong> ${sign.explanation_en || ''}</div>
        ${sign.explanation_hi ? `<div class="warning-exp-hi"><strong>Hinglish:</strong> ${sign.explanation_hi}</div>` : ''}
      `;
      el.warningSignsList.appendChild(card);
    });
  }

  function renderUrlForensics(urlAnalysis) {
    if (!urlAnalysis || !urlAnalysis.detected_urls || !urlAnalysis.detected_urls.length) {
      el.urlAnalysisCard.classList.add("hidden");
      return;
    }

    el.urlAnalysisCard.classList.remove("hidden");
    el.urlFindingsBody.innerHTML = "";

    urlAnalysis.detected_urls.forEach((url, i) => {
      const redFlag = (urlAnalysis.domain_red_flags && urlAnalysis.domain_red_flags[i]) || "Examined via heuristic domain inspection";
      const item = document.createElement("div");
      item.className = "url-item";
      item.innerHTML = `
        <div class="url-item-raw"><i class="fa-solid fa-arrow-up-right-from-square"></i> ${url}</div>
        <div class="url-item-tag"><i class="fa-solid fa-triangle-exclamation"></i> ${redFlag}</div>
      `;
      el.urlFindingsBody.appendChild(item);
    });
  }

  function renderRecommendedActions(actions) {
    el.recommendedActionsList.innerHTML = "";

    if (!actions.length) {
      el.recommendedActionsList.innerHTML = `<p style="color: var(--text-dim); font-size: 0.85rem;">No critical remedial actions needed.</p>`;
      return;
    }

    actions.forEach(act => {
      const row = document.createElement("div");
      row.className = "action-row";

      const urgency = act.urgency || "RECOMMENDED";
      row.innerHTML = `
        <span class="action-badge ${urgency}">${urgency}</span>
        <div class="action-texts">
          <div class="action-en">${act.action_en || ''}</div>
          ${act.action_hi ? `<div class="action-hi"><i class="fa-solid fa-globe"></i> ${act.action_hi}</div>` : ''}
        </div>
      `;
      el.recommendedActionsList.appendChild(row);
    });
  }

  // 10. Export Handlers
  function setupExportHandlers() {
    el.btnCopyReport.onclick = () => {
      if (!state.latestReportData) return;
      const md = formatReportAsMarkdown(state.latestReportData);
      navigator.clipboard.writeText(md).then(() => {
        window.showToast("Markdown Report copied to clipboard!", "success");
      });
    };

    el.btnDownloadJson.onclick = () => {
      if (!state.latestReportData) return;
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.latestReportData, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `cybershield-report-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      window.showToast("JSON report downloaded!", "info");
    };

    el.btnPrintReport.onclick = () => {
      window.print();
    };
  }

  function formatReportAsMarkdown(report) {
    let md = `# CyberShield AI - Threat Analysis Report\n`;
    md += `**Date:** ${new Date().toISOString()}\n`;
    md += `**Threat Risk Level:** ${report.overall_risk} (${report.risk_score}%)\n`;
    md += `**Category:** ${report.threat_category}\n`;
    md += `**Engine:** ${report.engine_used}\n\n`;
    
    md += `## Executive Summary\n${report.summary_en}\n\n`;
    md += `## Hinglish Summary\n${report.summary_hi}\n\n`;
    
    md += `## Detected Red Flags\n`;
    (report.warning_signs || []).forEach(sign => {
      md += `- **[${sign.severity}] ${sign.title}**\n`;
      if (sign.quote) md += `  > Quote: "${sign.quote}"\n`;
      md += `  - Reason: ${sign.explanation_en}\n`;
      if (sign.explanation_hi) md += `  - Hinglish: ${sign.explanation_hi}\n`;
    });
    md += `\n`;

    md += `## Recommended Actions\n`;
    (report.recommended_actions || []).forEach(act => {
      md += `- [${act.urgency}] ${act.action_en}\n`;
      if (act.action_hi) md += `  Hinglish: ${act.action_hi}\n`;
    });
    md += `\n`;

    md += `## Disclaimer\n${report.limitations_disclaimer}\n`;
    return md;
  }

  // Start Application
  init();
});
