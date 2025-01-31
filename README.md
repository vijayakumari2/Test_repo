# ZAP Report to GitHub Issues

This project parses a ZAP report and creates GitHub issues for high and medium severity vulnerabilities.

## Prerequisites

- Node.js
- npm (Node Package Manager)

## Setup

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Install the dependencies:
    ```sh
    npm init -y
    npm install axios cheerio dotenv
    ```

3. Create a [.env](http://_vscodecontentref_/0) file in the root directory with the following content:
    ```env
    GITHUB_OWNER='your-github-username'
    GITHUB_REPO='your-repository-name'
    GITHUB_TOKEN='your-github-token'
    ```

## Running the Scripts

### Parse ZAP Report

To parse the ZAP report and generate a [vulnerabilities.json](http://_vscodecontentref_/1) file, run:

```sh
node zap-report-to-github.js
 ```

Create GitHub Issues
To create GitHub issues from the vulnerabilities.json file, run:

```sh
node createGitHubIssues.js
```
