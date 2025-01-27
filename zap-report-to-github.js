const fs = require('fs');
const cheerio = require('cheerio');

const parseZapReport = (filePath) => {
    // Load the HTML content
    const htmlContent = fs.readFileSync(filePath, 'utf-8');
    const $ = cheerio.load(htmlContent);

    const vulnerabilities = [];

    // Loop through each vulnerability in the report
    $('table.results').each((index, table) => {
        const severity = $(table).find('th').first().text().trim(); // Extract severity
        const name = $(table).find('th').eq(1).text().trim(); // Vulnerability name

        // Extract URLs
        const urls = [];
        $(table).find('tr:contains("URL") td a').each((_, urlElement) => {
            urls.push($(urlElement).attr('href')); // Collect URLs
        });

        // Extract solution
        const solution = $(table).find('tr:contains("Solution") td').last().text().trim();

       // Only include High or Medium severity vulnerabilities
        if (severity === 'High' || severity === 'Medium') {
            vulnerabilities.push({
                name,
                severity,
                urls,
                solution,
            });
        }
    });

    // Write filtered vulnerabilities to a JSON file
    fs.writeFileSync('./vulnerabilities.json', JSON.stringify(vulnerabilities, null, 2));
    return vulnerabilities;
};

// Filepath to your ZAP report
const reportPath = './zap-report.html';

// Parse the report and log the results
const vulnerabilities = parseZapReport(reportPath);
console.log('Filtered vulnerabilities:', vulnerabilities);
