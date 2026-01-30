# Credentials and Secrets — Instructions ✅

Quick steps to safely add your own credentials and avoid committing secrets:

1. credentials.json
   - Copy `credentials.json.example` to `credentials.json` and replace the placeholders with your Google OAuth client credentials.
   - **Do not** commit `credentials.json` — it's now included in `.gitignore`.

2. token.json / attacker_token.json
   - These files are created by the OAuth flow. If you need to add them manually, use the `*.example` files as templates and **do not** commit the real files.

3. API Key for Gemini (LLM)
   - Put your Gemini API key into `api_key.txt` (file already contains a placeholder). Add the real key and keep `api_key.txt` in `.gitignore`.

4. Flask secret and default admin creds
   - Set environment variables for:
     - `FLASK_SECRET_KEY` — your Flask session secret
     - `DEFAULT_ADMIN_USER` and `DEFAULT_ADMIN_PASS` — optional default login for demos

5. Before pushing
   - Verify the following files are not committed: `credentials.json`, `token.json`, `attacker_token.json`, `api_key.txt`.
   - Run `git status` and ensure `.gitignore` is configured properly.

If you want, I can also add a script to generate `.env` and load values securely or add support for `python-dotenv`. Let me know if you want that. 🔧