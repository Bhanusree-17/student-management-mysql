# Student Management System (MySQL)

## Requirements
- Node.js
- MySQL Server (MySQL Workbench is optional)

## Setup
1. Create a MySQL database:
   ```sql
   CREATE DATABASE student_management;
   ```
2. Copy `.env.example` to `.env` and enter your MySQL password in `DB_PASSWORD`.
3. In this folder run:
   ```bash
   npm install
   npm start
   ```
4. Open http://localhost:3000. Login with `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`.

The server creates the admins and students tables automatically. Keep `.env` private and do not upload it to GitHub.
