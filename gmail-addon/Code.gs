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
    "subject": message.getSubject(),
    "sender": message.getFrom(),
    "date": message.getDate(),
    "body": message.getPlainBody(),
    "rawContent": message.getRawContent().substring(0, 5000) // First 5KB for header analysis
  };

  // NEEDS TO REPLACE THIS URL with actual Google Cloud Run URL later
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

  // Switch UI themes based on the 'label' categorized by our Python server
  switch(result.label) {
    case "safe":
      section.addWidget(CardService.newDecoratedText()
          .setText("<b>Email looks safe</b>")
          .setBottomLabel("Score: " + result.score + "/100 - Upwind verified.")
          .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.CONFIRMATION_NUMBER_ICON)));
      break;

    case "suspicious":
      section.addWidget(CardService.newTextWidget()
          .setText("<font color='#f1c40f'>⚠️ <b>Suspicious Content Detected</b></font>"));
      section.addWidget(CardService.newTextWidget()
          .setText("Risk Score: " + result.score + ". Verify the sender's identity."));
      break;

    case "malicious":
      section.addWidget(CardService.newTextWidget()
          .setText("<font color='#c0392b' size='Large'>🚨 <b>MALICIOUS EMAIL DETECTED!</b></font>"));
      section.addWidget(CardService.newTextWidget()
          .setText("<b>Critical Risk (" + result.score + "):</b> Potential phishing attempt detected. Do not click links!"));
      
      const deleteAction = CardService.newAction()
          .setFunctionName('deleteEmailAction')
          .setParameters({id: messageId});
          
      section.addWidget(CardService.newTextButton()
          .setText("DELETE THIS EMAIL")
          .setBackgroundColor("#c0392b")
          .setOnClickAction(deleteAction));
      break;
  }

  return [CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Upwind Security Scan"))
      .addSection(section)
      .build()];
}

/**
 * Moves the malicious email to the trash.
 * @param {Object} e The event object containing parameters.
 */
function deleteEmailAction(e) {
  const messageId = e.parameters.id;
  GmailApp.getMessageById(messageId).moveToTrash();
  
  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Email successfully moved to trash."))
      .build();
}

/**
 * Fallback UI in case of technical failure or network timeout.
 */
function createErrorCard() {
  const section = CardService.newCardSection()
      .addWidget(CardService.newTextWidget().setText("Unable to analyze email. Check your connection to the security server."));
  return [CardService.newCardBuilder().addSection(section).build()];
}
