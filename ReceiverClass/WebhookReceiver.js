/**
 * @File This contains the server process for receiving webhooks.
 * @Copyright 2023 Perforce Software Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this 
 * software and associated documentation files (the "Software"), to deal in the Software 
 * without restriction, including without limitation the rights to use, copy, modify, 
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to the following 
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies 
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

'use strict';

// NodeJS Modules
const https = require('https');
const fs = require('fs');
const { createHmac } = require('crypto');

// Third party modules
const express = require('express');

// Get https certs
const certs = {
    key: fs.readFileSync(__dirname + '/key.pem'),
    cert: fs.readFileSync(__dirname + '/cert.pem')
};

// Initialize variables
const requestListener = express();
const serverPort = process.argv.length > 2 ? process.argv[2] : 3000;
let statusCode = process.argv.length > 3 ? process.argv[3] : 200;
const consoleOutput = process.argv.length > 4 ? (process.argv[4] ? process.argv[4] === 'true' : false) : false;
const fileOutput = process.argv.length > 5 ? (process.argv[5] ? process.argv[5] === 'true' : false) : false;
const webhooksDomain = 'https://localhost';
const webhooksPath = '/';
let webhooksRecieved = [];

// Prepare file if writing output
let stream;
if (fileOutput === true) {
  fs.truncate('receivedWebhooks.txt', 0, ()=>{});
  stream = fs.createWriteStream('receivedWebhooks.txt', {flags:'a'});
}

// Clear message if needed
process.on('message', (message) => {
  if (message.clearHooks) {
    webhooksRecieved = [];
  }
  if (message.changeStatus) {
    statusCode = message.changeStatus;
  }
});

// Allow the reading of the json body
requestListener.use(express.json());

// Getting the webhook
requestListener.post(webhooksPath, async (request, response) => {
  const receivedWebhook = { headers: request.headers, body: request.body };
  response.sendStatus(statusCode);
  webhooksRecieved.push(receivedWebhook);

  // Get Secret Key (can update key value while app is running)
  let hashFunction;
  let sharedSecretKey;
  const sharedSecretKeyFile = fs.readFileSync(__dirname + '/../sharedSecretKey.txt', 'utf8').toString();
  if (sharedSecretKeyFile.length > 0 && sharedSecretKeyFile.indexOf(':') > 0) {
    hashFunction = sharedSecretKeyFile.split(':')[0].trim();
    sharedSecretKey = sharedSecretKeyFile.split(':')[1].trim();
  }

  // Only check signature if a shared key is used
  let signatureMatchText = '';
  if (hashFunction != undefined && sharedSecretKey != undefined)
  {
    // Get content used for the signatures
    let hashedString = '';
    hashedString += receivedWebhook['headers']['x-halm-webhook-version'];
    hashedString += receivedWebhook['headers']['x-halm-webhook-id'];
    hashedString += receivedWebhook['headers']['x-halm-webhook-timestamp'];
    hashedString += JSON.stringify(receivedWebhook['body']);

    // Get the hmac value
    const hmac = createHmac(hashFunction, sharedSecretKey);
    const signatureCheck = hmac.update(hashedString).digest('base64');

    // Check to see if one of the signatures match
    if (receivedWebhook['headers']['x-halm-webhook-signature-primary'] == signatureCheck) {
      signatureMatchText = 'The calculated signature matched the primary signature';
    } else if (receivedWebhook['headers']['x-halm-webhook-signature-secondary'] == signatureCheck) {
      signatureMatchText = 'The calculated signature matched the secondary signature';
    } else {
      signatureMatchText = 'The calculated signature did not match the primary or secondary signature';
    }
  }

  // Print to file and/or console
  if (consoleOutput === true) {
    console.log(`Webhook received at ${new Date().toISOString()}:`);
    console.log(`${JSON.stringify(receivedWebhook, null, 4)}`);
    if (signatureMatchText.length > 0) console.log(signatureMatchText);
    console.log('') // New line for each webhook
  }
  if (fileOutput === true) {
    stream.write(`Webhook received at ${new Date().toISOString()}: \n`);
    stream.write(`${JSON.stringify(receivedWebhook, null, 4)}\n`);
    if (signatureMatchText.length > 0) stream.write(signatureMatchText + '\n\n');
  }
  process.send(receivedWebhook);
});

// Place express into the https server
const server = https.createServer(certs, requestListener);

// Listen to the given port with the https sever
server.listen(serverPort, () => {
  if (consoleOutput === true) {
    console.log(`Listening at ${webhooksDomain}${webhooksPath} on port ${serverPort}`);
  }
});