'use strict';

const uuid = require('uuid');
const AWS = require('aws-sdk'); // eslint-disable-line import/no-extraneous-dependencies
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const dynamoDb = new AWS.DynamoDB.DocumentClient();

module.exports.register = (event, context, callback) => {
    const timestamp = new Date().getTime();
    const data = JSON.parse(event.body);
    data.password = bcrypt.hashSync(data.password, 8);

    const params = {
        TableName: process.env.USER_TABLE,
        Item: {
            name: data.name,
            phone: data.phone,
            email: data.email,
            password: data.password,
            createdAt: timestamp
        },
    };

    // write the todo to the database
    dynamoDb.put(params, (error) => {
        // handle potential errors
        if (error) {
        console.error(error);
        callback(null, {
            statusCode: error.statusCode || 501,
            headers: { 'Content-Type': 'text/plain' },
            body: 'Couldn\'t register user',
        });
        return;
        }

        // create a response
        const response = {
        statusCode: 200,
        body: JSON.stringify(params.Item),
        };
        callback(null, response);
    });
};

module.exports.login = (event, context, callback) => {
    const body = JSON.parse(event.body);
    const params = {
        TableName: process.env.USER_TABLE,
        Key: {
          email: body.email,
        },
    };

    dynamoDb.get(params, (error, result) => {
        // handle potential errors
        if (error) {
          console.error(error);
          callback(null, {
            statusCode: error.statusCode || 501,
            headers: { 'Content-Type': 'text/plain' },
            body: 'Couldn\'t login user.',
          });
          return;
        }

        const isValidPassword = bcrypt.compareSync(body.password, result.Item.password)

        if(isValidPassword){
            const secret = Buffer.from(process.env.JWT_SECRET, "base64");
            const token = jwt.sign({ email: body.email }, secret, {
                expiresIn: 86400 // expires in 24 hours
            });
            // create a response
            const response = {
                statusCode: 200,
                body: JSON.stringify({
                    user: result.Item,
                    token
                }),
            };
            callback(null, response);
        }
    });
}