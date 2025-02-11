const fs = require('fs');
const axios = require('axios');
require('dotenv').config(); // Load environment variables from .env file

// GitHub repository details
const GITHUB_OWNER = process.env.GITHUB_OWNER; // Use environment variables correctly
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

// GitHub API URL
const GITHUB_API_URL = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`;

// Function to create an issue
const createGitHubIssue = async (title, body) => {
  try {
    const response = await axios.post(
      GITHUB_API_URL,
      {
        title, // Issue title
        body,  // Issue body
      },
      {
        headers: {
          Authorization: `token ${GITHUB_TOKEN}`, // Authenticate with Personal Access Token
          Accept: 'application/vnd.github.v3+json',
        },
      }
    );

    console.log(`Issue created: ${response.data.html_url}`);
  } catch (error) {
    console.error('Error creating issue:', error.response ? error.response.data : error.message);
  }
};

// Main function to read vulnerabilities and create issues
const createIssuesFromVulnerabilities = () => {
  const vulnerabilities = JSON.parse(fs.readFileSync('./vulnerabilities.json', 'utf-8'));

  vulnerabilities.forEach((vulnerability) => {
    const title = `${vulnerability.severity} Vulnerability: ${vulnerability.name}`;
    const urls = vulnerability.urls.map((url) => `- ${url}`).join('\n');
    const body = `
### Vulnerability Details:
- **Name:** ${vulnerability.name}
- **Severity:** ${vulnerability.severity}

### Affected URLs:
${urls}

### Recommended Action:
${vulnerability.solution}

---

*Generated by automated ZAP scan reporting.*
    `;

    createGitHubIssue(title, body);
  });
};

// Run the script
createIssuesFromVulnerabilities();
