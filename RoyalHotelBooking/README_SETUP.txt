ROYAL HOTEL PROJECT - SETUP

Requirements:
- Node.js (LTS recommended)
- MongoDB Community Server running locally, OR a MongoDB Atlas connection string

1. Extract the ZIP file.
2. Open the extracted AIP-MINI-PROJECT-main folder in VS Code.
3. Open Terminal > New Terminal.
4. Run: npm install
5. Make sure MongoDB is running locally. The default connection is:
   mongodb://127.0.0.1:27017/fronye

   For MongoDB Atlas, create a file named .env in this folder and add:
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=replace_this_with_a_long_random_secret
   PORT=3000

6. Start the website:
   npm start
7. Open this address in Chrome:
   http://localhost:3000

IMPORTANT:
- Do not open index.html directly using file://. Run the Node server and open http://localhost:3000.
- Create an account using Sign Up, then log in. Booking requires a logged-in account.
- User passwords are stored as salted scrypt hashes, not plain text.
- Each booking is linked to the signed-in user in MongoDB.
- Set a long, private JWT_SECRET in .env before deploying publicly.
