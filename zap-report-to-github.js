const fs = require('fs');
const cheerio = require('cheerio');

const parseZapReport = (filePath) => {
    // Load the HTML content
    const htmlContent = fs.readFileSync(filePath, 'utf-8');
    const $ = cheerio.load(htmlContent);

    const vulnerabilities = [];

    // Find the alerts table
    $('table.alerts tr').each((index, element) => {
        // Skip the header row
        if (index === 0) return;

        // Extract the data
        const name = $(element).find('td a').text().trim(); // Name of the vulnerability
        const severityClass = $(element).find('td').eq(1).attr('class'); // Severity class
        const severityText = $(element).find('td').eq(1).text().trim(); // Severity text
        const instances = $(element).find('td').eq(2).text().trim(); // Number of instances

        // Parse severity from class or text
        let severity = '';
        if (severityClass.includes('risk-3')) severity = 'High';
        else if (severityClass.includes('risk-2')) severity = 'Medium';
        else if (severityClass.includes('risk-1')) severity = 'Low';
        else if (severityClass.includes('risk-0')) severity = 'Informational';

        // Only include High or Medium severity vulnerabilities
        if (severity === 'High' || severity === 'Medium') {
            vulnerabilities.push({
                name,
                severity,
                severityText,
                instances: parseInt(instances, 10),
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
