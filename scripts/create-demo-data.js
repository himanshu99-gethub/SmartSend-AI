import * as XLSX from 'xlsx';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '..', 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// 1. Create sample CSV
const csvContent = `Email,Name,Company,Role
sarah.connor@cyberdyne.tech,Sarah Connor,Cyberdyne Systems,Head of Security
alex.chen@innovate.co,Alex Chen,Innovate Labs,VP Engineering
priya.patel@horizonhealth.org,Priya Patel,Horizon Health,Operations Director
marcus.vance@vanguardfin.com,Marcus Vance,Vanguard Financial,Managing Partner
elena.rostova@aurorastudios.design,Elena Rostova,Aurora Studios,Creative Director
`;

fs.writeFileSync(path.join(DATA_DIR, 'sample-contacts.csv'), csvContent);

// 2. Create sample XLSX
const workbook = XLSX.utils.book_new();
const worksheetData = [
  ['Full Name', 'Work Email', 'Company Name', 'Industry'],
  ['Sarah Connor', 'sarah.connor@cyberdyne.tech', 'Cyberdyne Systems', 'AI & Robotics'],
  ['Alex Chen', 'alex.chen@innovate.co', 'Innovate Labs', 'Cloud Infrastructure'],
  ['Priya Patel', 'priya.patel@horizonhealth.org', 'Horizon Health', 'Healthcare Technology'],
  ['Marcus Vance', 'marcus.vance@vanguardfin.com', 'Vanguard Financial', 'Fintech'],
  ['Elena Rostova', 'elena.rostova@aurorastudios.design', 'Aurora Studios', 'Digital Design']
];
const worksheet = XLSX.utils.aoa_to_sheet(worksheetData);
XLSX.utils.book_append_sheet(workbook, worksheet, 'Executive Contacts');
XLSX.writeFile(workbook, path.join(DATA_DIR, 'sample-contacts.xlsx'));

console.log('Sample demo files created successfully:');
console.log('- data/sample-contacts.csv');
console.log('- data/sample-contacts.xlsx');
