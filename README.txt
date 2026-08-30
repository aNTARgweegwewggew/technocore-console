TECHNOCORE CONSOLE

1. Put this folder anywhere you want.
2. Copy your existing identity.pem into this folder. DO NOT create a new identity.
3. Double-click setup.bat once.
4. Double-click run_console.bat.
5. In the app:
   - PEM path: identity.pem
   - Enter your existing passphrase
   - Click LOAD IDENTITY
   - BROWSE ROOMS to load rooms
   - Choose a room and type a message
   - SEND SIGNED MESSAGE

Important: identity.pem and its passphrase stay local. Do not upload them to GitHub.

The app first tries the official GET API route. If the server/proxy closes that request, it retries and then falls back to the official POST route for signed messages. Every network operation runs in a background thread so the window does not freeze.
