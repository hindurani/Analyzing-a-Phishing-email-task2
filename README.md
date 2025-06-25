# Analyzing-a-Phishing-email-sample-task-2
Phishing Email Analysis - Cybersecurity Internship Task 2

Overview:

This repository contains the deliverables for Task 2 of the Eleyate Cybersecurity Internship, focused on analyzing a phishing email sample to identify phishing characteristics. The task involved examining a sample phishing email, identifying indicators such as spoofed sender addresses, suspicious links, and urgent language, and documenting findings in a report. This README provides a summary of the process, tools used, and key findings.

Task Objective:
Identify phishing characteristics in a suspicious email sample.
Deliverables: A report listing phishing indicators found, supported by screenshots and analysis outputs.
Tools: Email client (Gmail), free online header analyzer (Google Admin Toolbox), and URL/file scanner (VirusTotal).

Phishing Email Sample:
The sample used for analysis is a phishing email mimicking a PayPal account verification request. The email was sourced from CanIPhish to ensure safe, educational use. The sample is stored in this repository as phishing_email_sample.txt.

Analysis Process:
The analysis followed the task's mini-guide and was conducted as follows:
Obtained a Sample Phishing Email:
Source: CanIPhish free phishing email template library.
Sample: A fake PayPal email urging the recipient to verify their account.
Safety: The sample was downloaded as a text file to avoid interacting with live malicious content.
Examined Sender’s Email Address:
Sender: support@paypa1.com (misspelled "PayPal").
Finding: The domain paypa1.com is not associated with the official PayPal domain (paypal.com), indicating spoofing.

Analyzed Email Headers:
Tool: Google Admin Toolbox MessageHeader (https://toolbox.googleapps.com/apps/messageheader/).
Process: Copied the email headers from the sample and analyzed them for discrepancies.
Findings: SPF record failed, and the email originated from an unauthorized server (IP: 192.0.2.1). See header_analysis_screenshot.png.

Identified Suspicious Links and Attachments:
Links: A link displayed as www.paypal.com/login but pointing to http://paypa1-login.co.
Tool: VirusTotal (https://www.virustotal.com) flagged the URL as malicious.
Attachments: None present in the sample.
Findings: The mismatched URL is a clear phishing indicator. See virustotal_results.png.

Checked for Urgent or Threatening Language:
Example: “Your account will be locked in 24 hours unless you verify now.”
Finding: The email uses urgent language to pressure the recipient, a common social engineering tactic.

Noted Mismatched URLs:
Displayed: www.paypal.com/login; Actual: http://paypa1-login.co.
Finding: The discrepancy between the displayed and actual URLs confirms phishing intent.

Verified Spelling and Grammar Errors:
Examples: “Dear Costumer” (should be “Customer”) and “plese verify your acccount” (should be “please” and “account”).
Finding: Multiple spelling and grammar errors indicate a lack of professionalism typical of phishing emails.
Deliverables
Report: phishing_analysis_report.pdf contains a detailed analysis of the phishing indicators found, including sender spoofing, header discrepancies, suspicious links, urgent language, mismatched URLs, and spelling errors.

Supporting Files:
phishing_email_sample.txt: The phishing email sample in text format.
header_analysis_screenshot.png: Screenshot of the Google Admin Toolbox header analysis.
virustotal_results.png: Screenshot of the VirusTotal URL scan results.

Tools Used:
Gmail: To view and extract email headers from the sample.
Google Admin Toolbox MessageHeader: For analyzing email headers (free tool).
VirusTotal: To check the safety of URLs without visiting them (free tool).
Text Editor (VS Code): To draft the report and README.md.

Key Findings:
The analyzed email exhibited multiple phishing characteristics:
Spoofed sender address (support@paypa1.com).
Failed SPF record and unauthorized mail server in headers.
Mismatched URL (http://paypa1-login.co disguised as www.paypal.com).
Urgent language to manipulate the recipient.
Spelling and grammar errors indicating unprofessional content.
These traits confirm the email as a phishing attempt designed to steal user credentials.

Repository Structure:
phishing_email_sample.txt: Text file of the phishing email sample.
phishing_analysis_report.pdf: Detailed report of the analysis.
header_analysis_screenshot.png: Email header analysis output.
virustotal_results.png: URL scan results from VirusTotal.
README.md: This file, explaining the task and analysis process.

How to Reproduce:
Download a phishing email sample from a trusted source like CanIPhish.
Extract headers using an email client (e.g., Gmail’s “Show original”).
Analyze headers with Google Admin Toolbox MessageHeader.
Check links with VirusTotal without clicking them.
Review the email body for urgent language, mismatched URLs, and spelling errors.
Document findings in a report and upload to a GitHub repository.

Key Concepts Learned:
Phishing: Cyberattack to steal sensitive information via deceptive emails.
Email Spoofing: Forging sender addresses to appear legitimate.
Header Analysis: Checking SPF/DKIM records to verify email authenticity.
Social Engineering: Using urgency or fear to manipulate recipients.
Threat Detection: Identifying phishing indicators like suspicious links and errors.

Notes:
All tools used were free, as per the task guidelines.
The analysis was conducted in a safe environment, avoiding interaction with links or attachments.
Self-research was performed using online resources (e.g., CanIPhish, Phishing.org) to understand phishing tactics.
