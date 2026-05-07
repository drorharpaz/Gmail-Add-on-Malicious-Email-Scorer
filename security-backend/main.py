from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze_email():
    """
    Connectivity Test Endpoint.
    Receives email metadata from Gmail Add-on and returns a success response.
    """
    try:
        # Get the JSON payload sent from Google Apps Script
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No payload received"}), 400

        # Extract data for logging (to verify connectivity in Cloud Logs)
        sender = data.get('sender', 'Unknown Sender')
        subject = data.get('subject', 'No Subject')
        
        # Log the activity for observability
        print(f"--- New Analysis Request ---")
        print(f"Timestamp: {datetime.datetime.now()}")
        print(f"Sender: {sender}")
        print(f"Subject: {subject}")
        print(f"---------------------------")

        # Basic response logic for testing UI colors in the Add-on
        # If 'malicious' appears in the body, we return a high score
        body = data.get('body', '').lower()
        if "malicious" in body:
            result = {"score": 99, "label": "malicious"}
        else:
            result = {"score": 10, "label": "safe"}

        # Return the response in the format Code.gs expects
        return jsonify(result), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == '__main__':
    # Standard port for Cloud Run
    app.run(host='0.0.0.0', port=8080)
