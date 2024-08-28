const functions = require('firebase-functions');
const { spawn } = require('child_process');
const express = require('express');
const path = require('path');

const app = express();

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// Proxy requests to Flask app
app.all('/*', (req, res) => {
    const python = spawn('python3', ['../main.py']);

    python.stdout.on('data', (data) => {
        res.send(data.toString());
    });

    python.stderr.on('data', (data) => {
        console.error(data.toString());
    });

    python.on('close', (code) => {
        if (code !== 0) {
            res.status(500).send('Something went wrong');
        }
    });
});

exports.app = functions.https.onRequest(app);
