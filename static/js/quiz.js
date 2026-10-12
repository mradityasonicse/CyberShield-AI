/**
 * CyberShield AI - Interactive Quiz & Learn Mode Engine
 * Manages both standalone cyber awareness challenges and dynamic Gemini threat quizzes.
 */

const STANDALONE_QUIZ_DATA = [
  {
    id: 1,
    question: "You receive an SMS: 'Your Electricity Power will be disconnected tonight at 9:30 PM due to unpaid bill. Immediately call 9876543210'. What is the safest response?",
    options: [
      "Call the number right away to request an extension",
      "Do NOT call the number; open your official electricity board portal/app to check bill status",
      "Pay ₹100 to the number via UPI as temporary advance",
      "Forward the SMS to family members"
    ],
    correct_index: 1,
    explanation: "This is a rampant utility disconnection scam (Bijli Bill Scam). Scammers use tight deadlines (e.g. 9:30 PM) to create panic. Always verify via the electricity provider's official consumer portal."
  },
  {
    id: 2,
    question: "Which of the following links is an authentic PayPal login page?",
    options: [
      "http://paypal.account-verify.xyz/login",
      "https://www.paypal.com/signin",
      "https://paypal.com.verification-center.net",
      "http://192.168.1.55/paypal"
    ],
    correct_index: 1,
    explanation: "Look at the actual domain before the path: 'paypal.com'. Options A and C are subdomain tricks where the real domains are 'account-verify.xyz' and 'verification-center.net'."
  },
  {
    id: 3,
    question: "A caller claiming to be a Cyber Crime Police Officer video-calls you, shows a fake ID, and claims you are under 'Digital Arrest'. What should you do?",
    options: [
      "Transfer your bank funds to their 'clearing account' to prove innocence",
      "Stay on video call for 24 hours without telling anyone",
      "Immediately hang up, know that 'Digital Arrest' does not legally exist, and report to cybercrime.gov.in (1930)",
      "Send them a photo of your debit card and OTP"
    ],
    correct_index: 2,
    explanation: "Indian law and law enforcement agencies have repeatedly clarified: 'Digital Arrest' is an illegal scam extortion tactic. Genuine police never issue arrest warrants or demand money via Skype/WhatsApp video calls."
  },
  {
    id: 4,
    question: "When is it safe to share a One-Time Password (OTP) received on your phone?",
    options: [
      "When a polite bank executive calls requesting verification",
      "When someone says they sent you ₹5,000 by mistake and need the OTP to reverse it",
      "Never share OTP with any caller, chat agent, or unverified link",
      "When receiving a parcel delivery, share your Net Banking OTP"
    ],
    correct_index: 2,
    explanation: "An OTP is like a digital signature on a cheque. Sharing it authorizes transactions or account access. Legitimate service providers never ask for your confidential banking OTP over voice or SMS."
  },
  {
    id: 5,
    question: "What is the primary indicator of 'Artificial Urgency' in phishing emails?",
    options: [
      "The email contains technical words like SSL or HTTPS",
      "Threatening severe consequences (suspension, legal action, fine) if you don't act within hours",
      "The email is sent on a Monday morning",
      "The email has an image attached"
    ],
    correct_index: 1,
    explanation: "Attackers manufacture artificial urgency ('24 hours remaining', 'immediate action required') to bypass your critical thinking and prompt emotional, hasty clicks."
  }
];

class QuizManager {
  constructor() {
    this.standQuestions = [...STANDALONE_QUIZ_DATA];
    this.standScore = 0;
    this.standAnswered = 0;

    this.dynamicQuestions = [];
    this.dynamicScore = 0;
    this.dynamicAnswered = 0;
  }

  initStandaloneQuiz() {
    const container = document.getElementById("standAloneQuestionsList");
    const scoreDisplay = document.getElementById("standQuizScoreDisplay");
    const resetBtn = document.getElementById("btnResetStandQuiz");

    if (!container) return;

    this.standScore = 0;
    this.standAnswered = 0;
    if (scoreDisplay) scoreDisplay.textContent = `0 / ${this.standQuestions.length}`;
    container.innerHTML = "";

    this.standQuestions.forEach((q, idx) => {
      const qCard = document.createElement("div");
      qCard.className = "quiz-q-card glass-panel";
      qCard.id = `stand-q-${q.id}`;

      let optionsHtml = "";
      q.options.forEach((opt, optIdx) => {
        optionsHtml += `
          <button class="quiz-opt-btn" data-q-idx="${idx}" data-opt-idx="${optIdx}">
            <strong>${String.fromCharCode(65 + optIdx)}.</strong> ${opt}
          </button>
        `;
      });

      qCard.innerHTML = `
        <div class="quiz-q-text">
          <span style="color: var(--cyan-neon); margin-right: 6px;">Q${idx + 1}.</span> ${q.question}
        </div>
        <div class="quiz-options-list">
          ${optionsHtml}
        </div>
        <div class="quiz-q-explanation hidden" id="stand-exp-${q.id}">
          <strong><i class="fa-solid fa-lightbulb"></i> Explanation:</strong> ${q.explanation}
        </div>
      `;

      container.appendChild(qCard);
    });

    // Attach click listener
    container.querySelectorAll(".quiz-opt-btn").forEach(btn => {
      btn.addEventListener("click", (e) => this.handleStandaloneAnswer(e));
    });

    if (resetBtn) {
      resetBtn.onclick = () => this.initStandaloneQuiz();
    }
  }

  handleStandaloneAnswer(e) {
    const btn = e.currentTarget;
    const qIdx = parseInt(btn.dataset.qIdx);
    const optIdx = parseInt(btn.dataset.optIdx);
    const question = this.standQuestions[qIdx];
    const qCard = document.getElementById(`stand-q-${question.id}`);
    const expBox = document.getElementById(`stand-exp-${question.id}`);

    // Disable all options for this question
    const allOptBtns = qCard.querySelectorAll(".quiz-opt-btn");
    allOptBtns.forEach(b => b.disabled = true);

    const isCorrect = optIdx === question.correct_index;
    if (isCorrect) {
      btn.classList.add("correct");
      this.standScore++;
    } else {
      btn.classList.add("wrong");
      // Highlight the correct answer
      allOptBtns[question.correct_index].classList.add("correct");
    }

    this.standAnswered++;
    if (expBox) expBox.classList.remove("hidden");

    const scoreDisplay = document.getElementById("standQuizScoreDisplay");
    if (scoreDisplay) {
      scoreDisplay.textContent = `${this.standScore} / ${this.standQuestions.length}`;
    }

    if (this.standAnswered === this.standQuestions.length) {
      window.showToast?.(
        `Quiz Completed! You scored ${this.standScore}/${this.standQuestions.length}`,
        this.standScore >= 4 ? "success" : "info"
      );
    }
  }

  /**
   * Renders the 3 dynamic threat-specific questions returned by Gemini
   */
  renderDynamicQuiz(quizData) {
    const container = document.getElementById("quizQuestionsContainer");
    const scorePill = document.getElementById("quizScorePill");
    if (!container || !quizData || !quizData.length) return;

    this.dynamicQuestions = quizData;
    this.dynamicScore = 0;
    this.dynamicAnswered = 0;
    if (scorePill) scorePill.textContent = `Score: 0 / ${quizData.length}`;
    container.innerHTML = "";

    quizData.forEach((q, idx) => {
      const qCard = document.createElement("div");
      qCard.className = "quiz-q-card";
      qCard.id = `dyn-q-${idx}`;

      let optionsHtml = "";
      (q.options || []).forEach((opt, optIdx) => {
        optionsHtml += `
          <button class="quiz-opt-btn" data-dyn-q="${idx}" data-dyn-opt="${optIdx}">
            <strong>${String.fromCharCode(65 + optIdx)}.</strong> ${opt}
          </button>
        `;
      });

      qCard.innerHTML = `
        <div class="quiz-q-text">
          <span style="color: var(--purple-accent); margin-right: 6px;">Case Question ${idx + 1}:</span> ${q.question}
        </div>
        <div class="quiz-options-list">
          ${optionsHtml}
        </div>
        <div class="quiz-q-explanation hidden" id="dyn-exp-${idx}">
          <strong><i class="fa-solid fa-graduation-cap"></i> Lesson:</strong> ${q.explanation || 'Review the threat indicators carefully.'}
        </div>
      `;

      container.appendChild(qCard);
    });

    container.querySelectorAll(".quiz-opt-btn").forEach(btn => {
      btn.addEventListener("click", (e) => this.handleDynamicAnswer(e));
    });
  }

  handleDynamicAnswer(e) {
    const btn = e.currentTarget;
    const qIdx = parseInt(btn.dataset.dynQ);
    const optIdx = parseInt(btn.dataset.dynOpt);
    const question = this.dynamicQuestions[qIdx];
    const qCard = document.getElementById(`dyn-q-${qIdx}`);
    const expBox = document.getElementById(`dyn-exp-${qIdx}`);

    const allBtns = qCard.querySelectorAll(".quiz-opt-btn");
    allBtns.forEach(b => b.disabled = true);

    const isCorrect = optIdx === question.correct_index;
    if (isCorrect) {
      btn.classList.add("correct");
      this.dynamicScore++;
    } else {
      btn.classList.add("wrong");
      if (allBtns[question.correct_index]) {
        allBtns[question.correct_index].classList.add("correct");
      }
    }

    this.dynamicAnswered++;
    if (expBox) expBox.classList.remove("hidden");

    const scorePill = document.getElementById("quizScorePill");
    if (scorePill) {
      scorePill.textContent = `Score: ${this.dynamicScore} / ${this.dynamicQuestions.length}`;
    }

    if (this.dynamicAnswered === this.dynamicQuestions.length) {
      window.showToast?.(
        `Case Quiz Finished! Score: ${this.dynamicScore}/${this.dynamicQuestions.length}`,
        this.dynamicScore === 3 ? "success" : "info"
      );
    }
  }
}

// Global instance
window.cyberQuiz = new QuizManager();
