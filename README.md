# REST API Setup Guide

A comprehensive guide to setting up a TypeScript-based REST API with Express, MongoDB, and authentication.

## 🚀 Project Initialization

### 1. Initialize NPM Project
```bash
npm init -y
```

### 2. Install TypeScript Dependencies
```bash
npm i -D typescript ts-node nodemon
```

### 3. Configure TypeScript
Create `tsconfig.json`:
```json
{
    "compilerOptions": {
        "module": "NodeNext",
        "moduleResolution": "NodeNext",
        "baseUrl": "src",
        "outDir": "dist",
        "sourceMap": true,
        "noImplicitAny": true
    },
    "include": ["src/**/*"]
}
```

### 4. Configure Nodemon
Create `nodemon.json`:
```json
{
    "watch": ["src"],
    "ext": ".ts,.js",
    "exec": "ts-node ./src/index.ts"
}
```

### 5. Project Structure Setup
```bash
mkdir src
touch src/index.ts
```

### 6. Add Start Script
Add to `package.json` scripts section:
```json
{
    "scripts": {
        "start": "nodemon"
    }
}
```

### 7. Test Setup
Add to `src/index.ts`:
```typescript
console.log("Project setup successful!");
```

Run the project:
```bash
npm start
```

## 🌐 Express Server Configuration

### Install Express Dependencies
```bash
npm install express body-parser cookie-parser compression cors
npm install --save-dev @types/express @types/body-parser @types/cookie-parser @types/compression @types/cors
```

### Server Setup
Update `src/index.ts`:
```typescript
import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import cors from 'cors';

const app = express();

// Middleware configuration
app.use(cors({
    credentials: true,
}));

app.use(compression());
app.use(cookieParser());
app.use(bodyParser.json());

// Create HTTP server
const server = http.createServer(app);

server.listen(8080, () => {
    console.log('Server is running on port 8080');
});
```

## 🗄️ Database Integration

### Install MongoDB Dependencies
```bash
npm install mongoose
npm install -D @types/mongoose
```

### Database Connection
Add to `src/index.ts`:
```typescript
import mongoose from 'mongoose';

const MONGO_URL = 'your-database-url-here';

mongoose.Promise = Promise;
mongoose.connect(MONGO_URL);
mongoose.connection.on('error', (error: Error) => console.log(error));
mongoose.connection.on('open', () => console.log('Connected to MongoDB'));
```

## 📊 Project Structure

Create the following directory structure:

```
src/
├── index.ts
├── db/
│   └── users.ts
├── helpers/
│   └── index.ts
├── controllers/
│   ├── authentication.ts
│   └── users.ts
├── routes/
│   ├── index.ts
│   └── authentication.ts
└── middlewares/
    └── index.ts
```

### User Model Setup
Create `src/db/users.ts`:
```typescript
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    authentication: {
        password: { type: String, required: true, select: false },
        salt: { type: String, select: false },
        sessionToken: { type: String, select: false },
    },
});

export const UserModel = mongoose.model('User', UserSchema);

// Helper functions below
export const getUsers = () => UserModel.find();
export const getUserByEmail = (email: string) => UserModel.findOne({ email });
export const getUserBySessionToken = (sessionToken: string) => UserModel.findOne({ 'authentication.sessionToken': sessionToken });
export const getUserById = (id: string) => UserModel.findById(id);
export const createUser = (values: Record<string, any>) => new UserModel(values).save().then((user) => user.toObject());
export const deleteUserById = (id: string) => UserModel.findOneAndDelete({ _id: id });
export const updateUserById = (id: string, values: Record<string, any>) => UserModel.findByIdAndUpdate(id, values);
```

### Authentication Helpers
Install lodash for utility functions:
```bash
npm install lodash
npm install -D @types/lodash
```

Create `src/helpers/index.ts`:
```typescript
import crypto from 'crypto';

const SECRET = 'REST-API-SECRET';

export const random = () => crypto.randomBytes(128).toString('base64');
export const authentication = (salt: string, password: string): string => {
    return crypto.createHmac('sha256', [salt, password].join('/')).update(SECRET).digest('hex');
};
```

### Authentication Controller
Create `src/controllers/authentication.ts`:
```typescript
import express from 'express';
import { getUserByEmail, createUser } from '../db/users';
import { random, authentication } from '../helpers';

export const login = async (req: express.Request, res: express.Response) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const user = await getUserByEmail(email).select('+authentication.salt +authentication.password');

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        const expectedHash = authentication(user.authentication.salt, password);

        if (user.authentication.password !== expectedHash) {
            return res.status(403).json({ error: 'Invalid credentials' });
        }

        const salt = random();
        user.authentication.sessionToken = authentication(salt, user._id.toString());

        await user.save();

        res.cookie('REST-API-AUTH', user.authentication.sessionToken, { domain: 'localhost', path: '/' });

        return res.status(200).json(user).end();
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

export const register = async (req: express.Request, res: express.Response) => {
    try {
        const { email, password, username } = req.body;

        if (!email || !password || !username) {
            return res.status(400).json({ error: 'Email, password, and username required' });
        }

        const existingUser = await getUserByEmail(email);

        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const salt = random();
        const user = await createUser({
            email,
            username,
            authentication: {
                salt,
                password: authentication(salt, password),
            },
        });

        return res.status(200).json(user).end();
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};
```

### Users Controller
Create `src/controllers/users.ts`:
```typescript
import express from 'express';
import { deleteUserById, getUserById, getUsers, updateUserById } from '../db/users';

export const getAllUsers = async (req: express.Request, res: express.Response) => {
    try {
        const users = await getUsers();
        return res.status(200).json(users);
    } catch (error) {
        console.log(error);
        return res.status(400).json({ error: 'Failed to fetch users' });
    }
};

export const deleteUser = async (req: express.Request, res: express.Response) => {
    try {
        const { id } = req.params;

        const deletedUser = await deleteUserById(id);

        return res.status(200).json(deletedUser);
    } catch (error) {
        console.log(error);
        return res.status(400).json({ error: 'Failed to delete user' });
    }
};

export const updateUser = async (req: express.Request, res: express.Response) => {
    try {
        const { id } = req.params;
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const user = await getUserById(id);

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        user.username = username;
        await user.save();

        return res.status(200).json(user);
    } catch (error) {
        console.log(error);
        return res.status(400).json({ error: 'Failed to update user' });
    }
};
```

### Middleware Setup
Create `src/middlewares/index.ts`:
```typescript
import express from 'express';
import { get, merge } from 'lodash';
import { getUserBySessionToken } from '../db/users';

export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const sessionToken = req.cookies['REST-API-AUTH'];

        if (!sessionToken) {
            return res.status(403).json({ error: 'No session token provided' });
        }

        const existingUser = await getUserBySessionToken(sessionToken);

        if (!existingUser) {
            return res.status(403).json({ error: 'Invalid session token' });
        }

        merge(req, { identity: existingUser });

        return next();
    } catch (error) {
        console.log(error);
        return res.status(400).json({ error: 'Authentication failed' });
    }
};

export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
        const { id } = req.params;
        const currentUserId = get(req, 'identity._id') as string;

        if (!currentUserId) {
            return res.status(400).json({ error: 'User identity not found' });
        }

        if (currentUserId.toString() !== id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        next();
    } catch (error) {
        console.log(error);
        return res.status(400).json({ error: 'Authorization failed' });
    }
};
```

### Routes Configuration
Create `src/routes/authentication.ts`:
```typescript
import express from 'express';
import { login, register } from '../controllers/authentication';

export default (router: express.Router) => {
    router.post('/auth/register', register);
    router.post('/auth/login', login);
};
```

Create `src/routes/users.ts`:
```typescript
import express from 'express';
import { getAllUsers, deleteUser, updateUser } from '../controllers/users';
import { isAuthenticated, isOwner } from '../middlewares';

export default (router: express.Router) => {
    router.get('/users', isAuthenticated, getAllUsers);
    router.delete('/users/:id', isAuthenticated, isOwner, deleteUser);
    router.patch('/users/:id', isAuthenticated, isOwner, updateUser);
};
```

Create `src/routes/index.ts`:
```typescript
import express from 'express';
import authentication from './authentication';
import users from './users';

const router = express.Router();

export default (): express.Router => {
    authentication(router);
    users(router);
    return router;
};
```

### Final Server Configuration
Update `src/index.ts`:
```typescript
import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import cors from 'cors';
import mongoose from 'mongoose';
import router from './routes';

const app = express();

app.use(cors({
    credentials: true,
}));

app.use(compression());
app.use(cookieParser());
app.use(bodyParser.json());

const server = http.createServer(app);

server.listen(8080, () => {
    console.log('Server is running on port 8080');
});

const MONGO_URL = 'your-database-url-here';

mongoose.Promise = Promise;
mongoose.connect(MONGO_URL);
mongoose.connection.on('error', (error: Error) => console.log(error));
mongoose.connection.on('open', () => console.log('Connected to MongoDB'));

app.use('/api', router());
```

## 🛠️ API Endpoints

### Authentication
- **POST** `/api/auth/register` - Register a new user
- **POST** `/api/auth/login` - Login user

### Users (Protected Routes)
- **GET** `/api/users` - Get all users (requires authentication)
- **DELETE** `/api/users/:id` - Delete user (requires authentication + ownership)
- **PATCH** `/api/users/:id` - Update user (requires authentication + ownership)

## 🚀 Running the Application

1. Make sure MongoDB is running
2. Update the `MONGO_URL` in `src/index.ts` with your database connection string
3. Start the development server:
```bash
npm start
```

Your REST API will be available at `http://localhost:8080`

## 📝 Environment Variables

Consider using environment variables for sensitive data:
```typescript
const MONGO_URL = process.env.MONGO_URL || 'your-database-url-here';
const PORT = process.env.PORT || 8080;
const SECRET = process.env.SECRET || 'REST-API-SECRET';
```

## 🔧 Additional Recommendations

- Add input validation using libraries like `joi` or `express-validator`
- Implement rate limiting with `express-rate-limit`
- Add logging with `winston` or `morgan`
- Use environment variables for configuration
- Add API documentation with `swagger-ui-express`
- Implement proper error handling middleware

---

🎉 **Congratulations!** You now have a fully functional REST API with authentication, user management, and MongoDB integration.
