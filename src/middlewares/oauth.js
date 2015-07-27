"use strict";

var request = require("request");
var Promise = require('bluebird');

module.exports = {
    name: 'oauth',
    config: {
        endpoint: "",
        accessTokenExtractor: function(config, req, res) {
            var oAuthAccessToken;
            
            var reg = new RegExp("^bearer ");
            var authorization = req.headers.authorization;
            if (authorization && reg.test(authorization.toLowerCase())) {
                oAuthAccessToken = authorization.toLowerCase().replace("bearer ", "");
            }

            if (req.query.access_token) {
                oAuthAccessToken = req.query.access_token;
            }

            return oAuthAccessToken;
        },
        sendError: function(e, res){
            if(e.response){
                var err = JSON.parse(e.response.body);
                if(e.response.statusCode === 401){
                    res.setHeader('WWW-Authenticate', 'Bearer');
                }
                return res.status(e.response.statusCode||500).json(err);
            }
            res.setHeader('WWW-Authenticate', 'Bearer');
            return res.status(401).json('Access denied - accessToken needed');
        }
    },
    middleware: function(config, req, res) {

        if (config.endpoint == "") {
            throw new Error("oauth middleware wasn't configured")
        }
        return new Promise(function(resolve, reject) {
            var oAuthAccessToken = config.accessTokenExtractor(config, req, res);
 
            if (oAuthAccessToken) {
                return request.get(config.endpoint, {
                    auth: {
                        bearer: oAuthAccessToken
                    }
                }, function(error, response, body) {
                    if (!error && response.statusCode == 200) {

                        var user = JSON.parse(response.body);
                        return resolve(user);
                    }
                    return reject({error: error, response:response});
                });
            } 
            return reject({error:'no accessToken'});
        });
    }
}