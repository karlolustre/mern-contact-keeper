const express = require('express');
const connectDB = require('./config/db');

const app = express();

// connect database
connectDB();

//init middleware /"body parser"
app.use(express.json({ extended: false}));

app.get('/', (req, res) => res.send('Hello World'));

//define routes
app.use('/api/users', require('./routes/users'));
app.use('/api/auth', require('./routes/auth'));
app.use('/api/contacts', require('./routes/contacts'));


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
