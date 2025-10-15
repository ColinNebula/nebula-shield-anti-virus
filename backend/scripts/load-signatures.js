const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

// Database path
const DB_PATH = path.join(__dirname, '../data/nebula_shield.db');
const SIGNATURES_JSON = path.join(__dirname, '../data/virus-signatures.json');

console.log('=================================================');
console.log('  Nebula Shield - Virus Signature Database Loader');
console.log('  Created by Colin Nebula for Nebula3ddev.com');
console.log('=================================================\n');

// Load signature data
console.log('Loading signature database...');
const signatureData = JSON.parse(fs.readFileSync(SIGNATURES_JSON, 'utf8'));

console.log(`Version: ${signatureData.version}`);
console.log(`Total Signatures: ${signatureData.signature_count}`);
console.log(`Last Updated: ${signatureData.last_updated}\n`);

// Open database
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1);
    }
    console.log('Database connected successfully\n');
});

// Function to convert hex string to buffer
function hexToBuffer(hexString) {
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return Buffer.from(bytes);
}

// Clear existing signatures
db.run('DELETE FROM signatures', (err) => {
    if (err) {
        console.error('Error clearing signatures:', err.message);
        db.close();
        process.exit(1);
    }
    console.log('Cleared existing signatures\n');
    
    // Insert new signatures
    let successCount = 0;
    let errorCount = 0;
    
    const stmt = db.prepare(`
        INSERT INTO signatures (name, pattern, type, severity, description)
        VALUES (?, ?, ?, ?, ?)
    `);
    
    signatureData.signatures.forEach((sig, index) => {
        const pattern = hexToBuffer(sig.pattern);
        
        stmt.run(
            sig.name,
            pattern,
            sig.type,
            sig.severity,
            sig.description,
            (err) => {
                if (err) {
                    console.error(`❌ Error inserting ${sig.name}:`, err.message);
                    errorCount++;
                } else {
                    successCount++;
                    console.log(`✅ Loaded: ${sig.name} (${sig.type}, severity: ${sig.severity})`);
                }
                
                // Check if all signatures processed
                if (successCount + errorCount === signatureData.signatures.length) {
                    stmt.finalize();
                    
                    console.log('\n=================================================');
                    console.log(`Signature loading complete!`);
                    console.log(`✅ Successfully loaded: ${successCount}`);
                    console.log(`❌ Errors: ${errorCount}`);
                    console.log('=================================================\n');
                    
                    // Update configuration with version info
                    db.run(`
                        INSERT OR REPLACE INTO configuration (key, value)
                        VALUES ('signature_version', '${signatureData.version}')
                    `);
                    
                    db.run(`
                        INSERT OR REPLACE INTO configuration (key, value)
                        VALUES ('signature_count', '${signatureData.signature_count}')
                    `);
                    
                    db.run(`
                        INSERT OR REPLACE INTO configuration (key, value)
                        VALUES ('signature_last_updated', '${signatureData.last_updated}')
                    `, (err) => {
                        if (!err) {
                            console.log('Configuration updated with signature version info\n');
                        }
                        db.close((err) => {
                            if (err) {
                                console.error('Error closing database:', err.message);
                            } else {
                                console.log('Database closed successfully');
                                console.log('\n🎉 Virus signature database is now up to date!');
                                console.log('Your antivirus protection is enhanced with the latest threat definitions.\n');
                            }
                        });
                    });
                }
            }
        );
    });
});
