# Password Manager 5.1

Password Manager 5.1 is a comprehensive password management tool written in Python. It allows users to securely store, manage, and retrieve passwords, sensitive notes, encrypted files, banking details, and personal IDs. The application also includes features for password generation, health monitoring, and license activation.

## Features

### Password Management
- Save, retrieve, update, and delete passwords for different websites and services.
- Auto-generate strong passwords with customizable length and complexity.
- Import passwords from Excel files and export them to Excel or PDF for backup.
- Password health dashboard for analyzing password strength and reuse.

### File Encryption
- Encrypt and decrypt files using secure encryption algorithms.
- Manage encrypted files with options to view, decrypt, and delete them.
- Compatible with images and videos, allowing decrypted previews.

### Secure Notes
- Create, view, and delete encrypted secret notes.
- Export notes to text files for external storage.

### Banking Details Manager
- Save and manage banking details, including credit card and account information.
- Export banking details to Excel or PDF.

### Personal ID Management
- Save and manage personal IDs such as Aadhaar, PAN, driving licenses, and vehicle registrations.
- Add custom IDs with validation.

### License Management
- Supports trial and permanent license activation.
- Trial mode allows 10 uses before requiring an upgrade to a permanent license.

### Backup and Restore
- Backup user data, including passwords, notes, and banking details, as encrypted ZIP files.
- Restore data selectively or entirely from backup files.

### Security Features
- AES encryption using the `cryptography` library to protect sensitive data.
- Data integrity checks and device binding for license validation.

