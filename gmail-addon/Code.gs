// ---------- Gmail Add-on: Security Analysis Code ---------- //
// This script defines the main logic for a Gmail Add-on that analyzes
// email content for potential security threats using a remote backend service.

/**
 * Main entry point for the Gmail Add-on. 
 * Triggered when a user opens an email.
 * @param {Object} e The event object provided by Gmail.
 */
function onGmailMessageOpen(e) {
  const messageId = e.gmail.messageId;
  const accessToken = e.gmail.accessToken;
  
  // Set the access token to allow reading the current message
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  try {
    // Pass messageId to the analysis function
    // to allow it to fetch metadata
    const analysisResult = getAnalysisFromBackend(messageId); 
    
    // Build and return the UI Card based on the results from our server
    return buildSecurityCard(analysisResult, messageId);
    
  } catch (err) {
    console.error("Error during security analysis flow: " + err);
    return createErrorCard();
  }
}

/**
 * Fetches email metadata and sends it to the remote server.
 * @param {string} messageId The unique ID of the email.
 * @return {Object} The analysis JSON response from the backend.
 */
function getAnalysisFromBackend(messageId) {
  const message = GmailApp.getMessageById(messageId);
  
  // Construct a complex object with all relevant metadata for security analysis
  const payload = {
    "messageId": messageId,
    "subject": message.getSubject(), // Email subject for content analysis
    "sender": message.getFrom(), // Email address of the sender for domain analysis
    "date": message.getDate(), // Timestamp for temporal analysis
    "body": message.getPlainBody(), // Plain text content for quick analysis
    "htmlBody": message.getBody(), // Full HTML content for link extraction
    "rawContent": message.getRawContent() // Full Headers and raw source
  };

  // Use the public URL of deployed backend service
  const url = "https://upwind-security-service-1096141268910.me-west1.run.app/analyze"; 

  const options = {
    "method": "post",
    "contentType": "application/json",
    "headers": {
      "ngrok-skip-browser-warning": "true" // Bypass ngrok's initial warning page
    },
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true // Handle 4xx/5xx responses manually in code
  };

  const response = UrlFetchApp.fetch(url, options);
  const responseCode = response.getResponseCode();
  const responseText = response.getContentText();
  
  // Log the full response for debugging purposes
  if (responseCode !== 200) {
    console.error("Backend Error: " + responseCode + " - " + responseText);
    throw new Error("Backend reached but failed analysis.");
  }

  return JSON.parse(responseText);
}

/**
 * Construct the Card UI based on the backend analysis.
 * @param {Object} result The analysis result object (contains score and label).
 * @param {string} messageId The ID of the current email.
 */
function buildSecurityCard(result, messageId) {
  const section = CardService.newCardSection();

  // Dynamically build the UI based on the risk label returned by the backend
  switch(result.label) {
    case "safe":
      section.addWidget(CardService.newDecoratedText()
          .setText("<b><font color='#27ae60'>EMAIL LOOKS SAFE</font></b>")
          .setBottomLabel("Security Score: " + result.score + "/100")
          .setStartIcon(CardService.newIconImage()
              .setIcon(CardService.Icon.CONFIRMATION_NUMBER_ICON)));
      
      // FIXED: Use newTextParagraph instead of newTextWidget
      section.addWidget(CardService.newTextParagraph()
          .setText("Gmail Security Shield analyzed this message and found no immediate threats."));
      break;

    case "suspicious":
      section.addWidget(CardService.newDecoratedText()
          .setText("<b><font color='#f39c12'>SUSPICIOUS CONTENT</font></b>")
          .setBottomLabel("Risk Score: " + result.score + "/100")
          .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.VIDEO_CAMERA)));
      
      section.addWidget(CardService.newTextParagraph()
          .setText("Warning: This email contains patterns often seen in phishing. Proceed with caution."));
      break;

    case "malicious":
      section.addWidget(CardService.newDecoratedText()
          .setText("<b><font color='#c0392b'>🚨 MALICIOUS DETECTED!</font></b>")
          .setBottomLabel("Critical Risk Score: " + result.score)
          .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.NONE))); 

      section.addWidget(CardService.newTextParagraph()
          .setText("<b>Danger:</b> Our security engine identifies this as a high-risk phishing attempt."));
      
      const deleteAction = CardService.newAction()
          .setFunctionName('deleteEmailAction')
          .setParameters({id: messageId});
          
      section.addWidget(CardService.newTextButton()
          .setText("DELETE PERMANENTLY")
          .setBackgroundColor("#c0392b")
          .setOnClickAction(deleteAction));
      break;
  }

  // Build and return the card with the appropriate header and content
  return [CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader()
          .setTitle("Gmail Security Shield")
          .setSubtitle("AI-Powered Threat Analysis"))
      .addSection(section)
      .build()];
}

/**
 * Fallback UI for technical failures.
 * Displayed when the backend is unreachable or returns an error.
 * Provides a user-friendly message and encourages retrying later.
 * @return {Card[]} An array containing a single error card.
 */
function createErrorCard() {
  const section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph() // FIXED: Use newTextParagraph
          .setText("Unable to analyze email. Check your connection to the security server."));
          
  return [CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Gmail Security Shield"))
      .addSection(section)
      .build()];
}