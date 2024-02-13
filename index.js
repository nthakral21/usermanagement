const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const jwtSecret = crypto.randomBytes(32).toString('hex');

const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({extended: false})); 
const connect = mongoose.connect('mongodb://localhost:27017/selfmade')

connect.then(() => {
    console.log("Database connected");
})
.catch(() =>{
    console.log("Database not connected");
})
const LoginSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
    },
});

const UserModel = new mongoose.model("users",LoginSchema);

// 

//Register user 
app.post("/register", async (req, res) => {
    try {
        const userData = {
            username: req.body.username,
            password: req.body.password,
            email: req.body.email,
            phone: req.body.phone
        };
        const existingUser = await UserModel.findOne({username: userData.username})
        if(existingUser){
            res.send("user already exist please login or change username");
        }
        else{
        const hashedPassword = await bcrypt.hash(userData.password, 10)
        userData.password = hashedPassword;
        const newUser = new UserModel(userData);
        await newUser.save();
        console.log("User registered successfully");
        res.redirect('/login');
        }}
     catch (error) {
        console.error("Error registering user:", error);
        res.status(500).send("Internal Server Error");
    }
});
app.post("/login", async (req, res) => {
    try {
        const user = await UserModel.findOne({ username: req.body.username });

        if (!user) {
            return res.send("Username not found");
        }

        const isPasswordMatch = await bcrypt.compare(req.body.password, user.password);

        if (isPasswordMatch) {
             // Generate JWT token
             const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });

             // Send the token as a cookie or in the response
             res.cookie('jwt', token);
             // Alternatively, you can send it in the response body: res.json({ token });
            res.redirect('/evai');
        } else {
            res.send("Wrong password");
        }
    } catch (error) {
        console.error("Error during login:", error);
        res.send("Internal Server Error");
    }
});

app.post('/addUser', async (req, res) => {
    const { username, email,phone,password } = req.body;
  
    // Create a new user
    const newUser = new UserModel ({
      username,
      email,
      phone,
      password
    });
    const hashedPassword = await bcrypt.hash(newUser.password, 10)
    newUser.password = hashedPassword;
    // Save the user to the database
    newUser.save()
      .then(() => {
        res.send('user Added SuccessFull');
      })
      .catch((error) => {
        console.error('Error saving user:', error.message);
        res.send('Error saving user');
      });
  });

  app.get('/showAllUsers', (req, res) => {
    // Find all users in the database
    UserModel.find({})
      .then((users) => {
        // Display users in a list
        let userList = '<ul>';
        users.forEach((user) => {
          userList += `<li>${user.username}: ${user.email}: ${user.phone}: </li>`;
        });
        userList += '</ul>';
        res.send(userList);
      })
      .catch((error) => {
        console.error('Error fetching users:', error.message);
        res.send('Error fetching users');
      });
  });

  app.post('/updateUser', async (req, res) => {
    try {
        const { username, email, phoneNumber, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const updatedUser = await UserModel.findOneAndUpdate(
            { username },
            { email, phone: phoneNumber, password:hashedPassword },
            { new: true }
        );

        if (!updatedUser) {
            return res.send('User not found');
        }

        res.send('User updated successfully');
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/deleteUser', async (req, res) => {
    try {
        const { deleteUsername } = req.body;
        const deletedUser = await UserModel.findOneAndDelete({ username: deleteUsername });

        if (!deletedUser) {
            return res.send('User not found');
        }

        res.send('User deleted successfully');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Internal Server Error');
    }
});

function authenticateJWT(req, res, next) {
    const token = req.cookies.jwt;

    if (!token) {
        return res.status(401).send("Unauthorized");
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).send("Forbidden");
        }

        req.user = user;
        next();
    });
}
app.get('/logout', (req, res) => {
    res.clearCookie('jwt');
    res.redirect('/');
});
// middleware to serve static files from directory
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});
app.get('/evai', authenticateJWT,(req, res) => {

    res.sendFile(path.join(__dirname, 'views', 'evai.html'));
});
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.get('/redirect-to-login', (req, res) => {
    res.redirect('/login');
});
app.get('/redirect-to-register', (req, res) => {
    res.redirect('/register');
});



const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
