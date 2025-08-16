# Islamic Stories Blogging Website

A full-stack MERN (MongoDB, Express.js, React.js, Node.js) blogging platform specifically designed for sharing Islamic stories, teachings, and content.

## 🌟 Features

### Frontend Features
- **Modern React Interface** with responsive design
- **Rich Text Editor** with EditorJS for content creation
- **Real-time Auto-save** functionality for drafts
- **Image Upload** with Cloudinary integration
- **User Authentication** with JWT tokens
- **Admin Dashboard** for content management
- **Search and Filter** functionality
- **Category Management** for organized content
- **Comment System** with nested replies
- **Like and Bookmark** functionality
- **Responsive Design** for all devices

### Backend Features
- **RESTful API** with Express.js
- **MongoDB Database** with Mongoose ODM
- **JWT Authentication** and authorization
- **Image Upload** handling with Cloudinary
- **Draft Management** system
- **Blog ID Generation** with validation
- **Error Handling** and validation
- **Rate Limiting** and security measures

## 🚀 Quick Start

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or cloud)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <your-repository-url>
   cd iblogSite-mern
   ```

2. **Install dependencies**
   First, install root dependencies. Then navigate into each sub-project and install their dependencies.

   ```bash
   # Install root dependencies
   npm install

   # Install admin-panel dependencies
   cd admin-panel
   npm install
   cd .. # Go back to iblogSite-mern directory

   # Install mern-blogging-website frontend dependencies
   cd mern-blogging-website/frontend
   npm install
   cd ../.. # Go back to iblogSite-mern directory

   # Install mern-blogging-website server (backend) dependencies
   cd mern-blogging-website/server
   npm install
   cd ../.. # Go back to iblogSite-mern directory
   ```

3. **Environment Setup**
   The backend server requires environment variables to run. You'll create a `.env` file in the `iblogSite-mern/mern-blogging-website/server` directory.

   - **Navigate to the server directory:**
     ```bash
     cd mern-blogging-website/server
     ```
   - **Copy the template file:**
     ```bash
     cp env-template.txt .env
     ```
   - **Edit the `.env` file:** Open the newly created `.env` file and fill in your specific configurations. An example `.env` file content with explanations is provided in the `Configuration` section below.

4. **Database Setup**
   - Set up your MongoDB database. You can use a local MongoDB instance or a cloud service like MongoDB Atlas.
   - If using MongoDB Atlas, ensure your current IP address is whitelisted in your Atlas project's network access settings to allow connections.
   - Update the `MONGO_URI` variable in your `.env` file with your MongoDB connection string.

5. **Cloudinary Setup** (for image uploads)
   - Create a free account on [Cloudinary](https://cloudinary.com/).
   - Obtain your Cloud Name, API Key, and API Secret from your Cloudinary dashboard.
   - Add these credentials to the respective `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, and `CLOUDINARY_API_SECRET` variables in your `.env` file.

### Running the Application

To run the full application, you need to start the backend server, the main frontend, and optionally the admin panel, each in a separate terminal.

1. **Start the Backend Server**
   - Open a new terminal.
   - Navigate to the backend server directory:
     ```bash
     cd iblogSite-mern/mern-blogging-website/server
     ```
   - Run the server in development mode (with `nodemon` for auto-restarts):
     ```bash
     npm run dev
     ```
   - The backend API will be accessible at `http://localhost:3000`.

2. **Start the Main Frontend Development Server**
   - Open another new terminal.
   - Navigate to the main frontend directory:
     ```bash
     cd iblogSite-mern/mern-blogging-website/frontend
     ```
   - Start the frontend development server:
     ```bash
     npm run dev
     ```
   - The main frontend application will be accessible at `http://localhost:5173`.

3. **Start the Admin Panel (Optional)**
   - Open a third new terminal.
   - Navigate to the admin panel directory:
     ```bash
     cd iblogSite-mern/admin-panel
     ```
   - Start the admin panel development server:
     ```bash
     npm run dev
     ```
   - The admin panel will typically be accessible at `http://localhost:5174` (check your `admin-panel/vite.config.js` for the exact port if it differs).

## 📁 Project Structure

```
islamic-stories-website/
├── admin-panel/                   # Admin panel (React.js)
│   ├── src/                       # Source code for the admin panel
│   └── package.json               # Admin panel dependencies and scripts
├── mern-blogging-website/
│   ├── frontend/                  # Main React.js frontend
│   │   ├── src/                   # Source code for the main frontend
│   │   └── package.json           # Main frontend dependencies and scripts
│   ├── server/                    # Node.js Express.js backend
│   │   ├── Schema/                # MongoDB Mongoose schemas
│   │   ├── utils/                 # Utility functions
│   │   └── server.js              # Main backend server file
│   └── package.json               # Backend dependencies and scripts
├── .gitignore                     # Git ignore file
└── README.md                      # Project README file
```

## 🔧 Configuration

### Environment Variables

You need to create a `.env` file in the `iblogSite-mern/mern-blogging-website/server` directory. This file will store sensitive information and configuration settings.

Here's an example of the `.env` file content. Replace the placeholder values with your actual credentials and settings:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# MongoDB Configuration
# Your MongoDB connection string. For MongoDB Atlas, it will look like:
# mongodb+srv://<username>:<password>@<cluster-url>/<database-name>?retryWrites=true&w=majority&appName=<your-app-name>
MONGO_URI=mongodb+srv://your_username:your_password@your_cluster_url/your_database_name?retryWrites=true&w=majority&appName=your_app_name

# JWT Configuration
# A strong, random secret key for signing JWT tokens.
SECRET_ACCESS_KEY=your-long-random-secret-key-here
# Audience for JWT tokens (e.g., your application's domain)
JWT_AUDIENCE=islamic-stories-blog
# Issuer of JWT tokens (e.g., your application's name)
JWT_ISSUER=islamic-stories-blog

# Cloudinary Configuration
# Your Cloudinary cloud name
CLOUDINARY_CLOUD_NAME=your-cloud-name
# Your Cloudinary API Key
CLOUDINARY_API_KEY=your-api-key
# Your Cloudinary API Secret
CLOUDINARY_API_SECRET=your-api-secret

# Frontend URL (for CORS - Cross-Origin Resource Sharing)
# The URL where your main frontend application is running
FRONTEND_URL=http://localhost:5173
# Admin Panel URL (for CORS - if applicable and running separately)
# The URL where your admin panel application is running
ADMIN_PANEL_URL=http://localhost:5174
```

## 🛠️ Development

### Available Scripts

**Backend (server directory):**
```bash
npm start          # Start production server
npm run dev        # Start development server with nodemon
npm test           # Run tests
```

**Frontend (blogging website - frontend directory):**
```bash
npm run dev        # Start development server
npm run build      # Build for production
npm run preview    # Preview production build
```

### Database Management

The project includes several database management scripts:

- `test-draft-editing.js` - Test draft editing functionality
- `test-draft-saving.js` - Test draft saving functionality
- `test-blog-id-generation.js` - Test blog ID generation
- `fix-draft-blogids.js` - Fix missing blog IDs

## 🔒 Security Features

- JWT-based authentication
- Password hashing with bcrypt
- Input validation and sanitization
- CORS configuration
- Rate limiting
- Environment variable protection

## 📱 Responsive Design

The application is fully responsive and works on:
- Desktop computers
- Tablets
- Mobile phones
- All modern browsers

## 🚀 Deployment

### Frontend Deployment
1. Build the frontend: `npm run build`
2. Deploy the `dist` folder to your hosting service
3. Configure environment variables for production

### Backend Deployment
1. Set up a Node.js hosting service (Heroku, Vercel, etc.)
2. Configure environment variables
3. Set up MongoDB Atlas for database
4. Deploy the server code

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the documentation files in the project
2. Review the test scripts for examples
3. Check the console logs for error messages
4. Create an issue in the repository

## 🔄 Recent Updates

### Latest Fixes
- ✅ Fixed draft editing functionality
- ✅ Resolved duplicate placeholder text issue
- ✅ Added publish button to review section
- ✅ Enhanced editor initialization logic
- ✅ Improved error handling and validation

### Known Issues
- None currently reported

## 📊 Performance

- Optimized image uploads with Cloudinary
- Efficient database queries with indexing
- Lazy loading for better performance
- Cached static assets

---

**Built with ❤️ for the Islamic community** 