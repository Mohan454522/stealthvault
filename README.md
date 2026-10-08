# StealthVault

StealthVault is a secure, browser-based file vault. It encrypts and stores files directly within your browser, ensuring top-tier privacy and fast access. 

## Features
- **Browser-Based Encryption**: Uses local browser processing for security.
- **Custom Vault Format (v6)**: Specialized binary format optimized for rapid decryption and chunking.
- **Service Workers**: Employs Web Workers for background processing.
- **Cloudflare Pages**: Optimized for deployment on Cloudflare Pages.

## Deployment
StealthVault is built to be deployed on Cloudflare Pages.
- **Main Branch**: Automatically deployed to production.
- **Dev Branch**: Used for staging and testing.

## Recovery
A local recovery blueprint is generated to help understand the Vault Format v6 for emergency extraction. Do not commit your personal Recovery_Blueprint.txt.
