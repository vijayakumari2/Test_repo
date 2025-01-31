const fs = require('fs');
const axios = require('axios');
require('dotenv').config();
const fuzzy = require('fuzzy');

const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;  // Store API Key in .env
const GITHUB_API_URL = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`;

/**
 * Calls AI to generate a structured GitHub issue based on ZAP vulnerabilities.
 */
const callAIForAnalysis = async (vulnerabilities) => {
    const prompt = `You are a security expert. Given the following security vulnerabilities extracted from a ZAP security scan, generate a well-structured GitHub issue with:

    - A clear issue title
    - A summary of the vulnerabilities found
    - A breakdown categorized by severity
    - Suggested solutions
    - Next steps for the development team

    Here is the vulnerability data:\n\n${JSON.stringify(vulnerabilities, null, 2)}
    
    Format your response as follows:
    
    TITLE: <Title of GitHub Issue>
    
    BODY:
    ---
    <Well-structured issue description>
    ---`;

    try {
        const response = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'openai/gpt-4o-mini',  // Use the appropriate model ID
                messages: [{ role: 'user', content: prompt }],
                max_tokens: 800,
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENAI_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        const aiResponse = response.data.choices[0].message.content;

        // Extract Title and Body from AI response
        const titleMatch = aiResponse.match(/TITLE:\s*(.+)/);
        const bodyMatch = aiResponse.match(/BODY:\s*---([\s\S]*)---/);

        const title = titleMatch ? titleMatch[1].trim() : "Security Vulnerabilities from ZAP Scan";
        const body = bodyMatch ? bodyMatch[1].trim() : aiResponse;

        return { title, body };
    } catch (error) {
        console.error('Error calling AI:', error);
        return { title: 'Security Vulnerabilities from ZAP Scan', body: 'AI analysis failed.' };
    }
};

/**
 * Calls AI to extract relevant vulnerability data from the HTML content.
 */
const callAIForHtmlAnalysis = async (htmlContent) => {
    const prompt = `You are a security expert. Below is the content of a ZAP security scan report in HTML format. Please extract the following information for all vulnerabilities with severity High or Medium:

    - Name of the vulnerability
    - Severity
    - URL(s) affected
    - Suggested solution

    Here is the HTML content of the report:\n\n${htmlContent}

    Please respond with a structured JSON array like this:
    [
        {
            "name": "<Vulnerability Name>",
            "severity": "<Severity Level>",
            "urls": ["<URL1>", "<URL2>"],
            "solution": "<Suggested Solution>"
        },
        ...
    ]`;

    try {
        const response = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'openai/gpt-4o-mini',
                messages: [{ role: 'user', content: prompt }],
                max_tokens: 1500,
            },
            {
                headers: {
                    'Authorization': `Bearer ${OPENAI_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        const aiResponse = response.data.choices[0].message.content;

        // Clean up any extra characters (e.g., backticks, markdown) before parsing as JSON
        const cleanedResponse = aiResponse.replace(/```json|```/g, '').trim();

        // Try parsing the cleaned response
        const extractedVulnerabilities = JSON.parse(cleanedResponse);

        return extractedVulnerabilities;

    } catch (error) {
        console.error('Error calling AI for HTML analysis:', error);
        return [];
    }
};

/**
 * Compares the issue body with the newly generated body using fuzzy matching.
 */
const isDuplicateUsingFuzzy = (existingBody, newBody) => {
    const results = fuzzy.filter(newBody, [existingBody]);
    return results.length > 0 && results[0].score > 0.8; // Threshold of 80% similarity
};

/**
 * Checks for duplicate issues by comparing both title and body content.
 */
const checkForDuplicateIssue = async (title, bodyContent) => {
    try {
        // Fetch the list of open issues
        const response = await axios.get(
            `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`,
            {
                params: {
                    state: 'open', // Check only open issues
                    sort: 'created', // Sort by creation date, newest first
                    direction: 'desc', // Newest first
                    per_page: 10, // Limit to the most recent 10 issues
                },
                headers: {
                    'Authorization': `Bearer ${GITHUB_TOKEN}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        const issues = response.data;

        // Normalize the title and body for comparison (case-insensitive)
        const normalizedTitle = title.trim().toLowerCase();
        const normalizedBody = bodyContent.trim().toLowerCase();

        // Loop through the most recent issues to check for duplicates
        for (let issue of issues) {
            const issueTitleNormalized = issue.title.trim().toLowerCase();
            const issueBodyNormalized = issue.body ? issue.body.trim().toLowerCase() : '';

            // Check for a duplicate based on title or body content using fuzzy matching for body
            if (
                (issueTitleNormalized === normalizedTitle || issueTitleNormalized.includes(normalizedTitle)) ||
                isDuplicateUsingFuzzy(issueBodyNormalized, normalizedBody)
            ) {
                console.log(`Duplicate issue found: ${issue.html_url}`);
                return true; // Duplicate issue found
            }
        }

        return false; // No duplicate found
    } catch (error) {
        console.error('Error checking for duplicate issue:', error);
        return false; // If there's an error, assume no duplicate
    }
};

/**
 * Creates a GitHub issue using AI-generated title and body.
 */
const createGitHubIssue = async (title, body) => {
    const isDuplicate = await checkForDuplicateIssue(title, body);

    if (isDuplicate) {
        console.log('Issue not created because it is a duplicate.');
        return; // Skip creating the issue if it's a duplicate
    }

    const issueData = {
        title: title,
        body: body,
        labels: ['security', 'zap', 'vulnerability'], // Add relevant labels
    };

    try {
        const response = await axios.post(
            GITHUB_API_URL,
            issueData,
            {
                headers: {
                    'Authorization': `Bearer ${GITHUB_TOKEN}`,
                    'Content-Type': 'application/json',
                },
            }
        );
        console.log(`GitHub Issue Created: ${response.data.html_url}`);
    } catch (error) {
        console.error('Error creating GitHub issue:', error.response ? error.response.data : error);
    }
};

/**
 * Parses a ZAP security scan report (HTML) and extracts high/medium severity vulnerabilities using AI.
 */
const parseZapReport = async (filePath) => {
    try {
        const htmlContent = fs.readFileSync(filePath, 'utf-8');
        
        // Get AI-generated vulnerability data
        const vulnerabilities = await callAIForHtmlAnalysis(htmlContent);

        if (vulnerabilities.length === 0) {
            console.log('No high or medium severity vulnerabilities found.');
            return;
        }

        console.log('Extracted Vulnerabilities:', vulnerabilities);

        // Get AI-generated issue title and body
        const { title, body } = await callAIForAnalysis(vulnerabilities);

        // Create GitHub Issue only if it's not a duplicate
        await createGitHubIssue(title, body);

    } catch (error) {
        console.error('Error parsing ZAP report:', error);
    }
};

// Run the script with the given ZAP report path
const reportPath = './zap-report.html';
parseZapReport(reportPath);
