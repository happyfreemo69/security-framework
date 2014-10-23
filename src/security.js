module.exports = function(oauth, settings) {
    return new Security(oauth, settings);
}

var _ = require('lodash'),
        basic_auth = require('http-auth');
var request = require("request");
var Promise = require('bluebird');
/**
 * AuthoriseClient
 *
 */
function Security(settings) {

    //this.settings = settings;
    this.rules = settings.rules;
    this.methods = settings.methods;
    this.allowedMethodNames = [];
    this.validationsForMethod = [];
    this.optionsForMethod = [];

    this.registerDefaultValidationsForMethod();
    return this;
}

/**
 * Validate configuration
 * @returns {undefined}
 */
Security.prototype.validate = function() {
    var self = this;

    // Verifiy settings
    if (this.methods == undefined || this.rules == undefined) {
        throw new Error("security configuration error, missing methods or rules")
    }

    // Throw error if methods for rules is not found
    self.allowedMethodNames = _.union(self.allowedMethodNames, _.keys(this.methods));

    // register middlewares
    self.addValidationMethod(this.methods);

    _.each(this.rules, function(rules) {
        var methodRules = rules.methods;

        // First, we check is no new method are not configured for rule
        _.each(methodRules, function(method) {
            if (_.isPlainObject(method)) {
                self.allowedMethodNames = _.union(self.allowedMethodNames, _.keys(method));
                self.addValidationMethod(method);
            }
        });

        // Second we check if methods for rules are know
        _.each(methodRules, function(method) {
            if (_.isString(method)) {
                if (!_.contains(self.allowedMethodNames, method)) {
                    throw new Error('"' + method + '"' + " is not a validation method")
                }
            }
        })
    });
}

Security.prototype.addValidationMethod = function(objects) {

    var self = this;
    _.forIn(objects, function(object, key) {

        if (object.extends != undefined) {

            // try to search on default providers with name
            if (self.validationsForMethod[object.extends] != undefined) {

                object.validation = self.validationsForMethod[object.extends];

                var defaultConfig = _.cloneDeep(self.optionsForMethod[object.extends])
                object.config = _.merge(defaultConfig, object.config);

            } else {
                throw new Error("unknow validation method for key " + object.validation)
            }
        }

        // object must have a validation function
        if (object.validation == undefined) {
            // try to search on default providers with name
            if (self.validationsForMethod[key] != undefined) {
                object.validation = self.validationsForMethod[key];
            } else {
                throw new Error("unknow validation method for key " + key)
            }
        }



        self.validationsForMethod[key] = object.validation;
        self.optionsForMethod[key] = object.config;
    })
}

Security.prototype.registerDefaultValidationsForMethod = function() {
    var self = this;

    self.validationsForMethod["oauth"] = self.middlewareOauth;
    self.validationsForMethod["http"] = self.middlewareHttpBasic;
    self.validationsForMethod["guest"] = function(config, req, res) {

        return new Promise(function(resolve, reject) {
            resolve();
        })
    };

    self.allowedMethodNames.push("oauth");
    self.allowedMethodNames.push("http");
    self.allowedMethodNames.push("guest");
}

Security.prototype.middlewareOauth = function(config, req, res) {

    if (config === undefined) {
        throw new Error("oauth middleware wasn't configure")
    }

    return new Promise(function(resolve, reject) {
        var oAuthAccessToken = "";

        // if user provided method to extract access token, use it
        if (config.accessTokenExtractor != undefined) {
            oAuthAccessToken = config.accessTokenExtractor(config, req, res);
        } else { // Default method are in "authorization" header with bearer theaccestoken
            var reg = new RegExp("^bearer ");
            var authorization = req.headers.authorization;
            if (authorization && reg.test(authorization.toLowerCase())) {
                oAuthAccessToken = authorization.toLowerCase().replace("bearer ", "");
            }

            if (req.query.access_token) {
                oAuthAccessToken = req.query.access_token;
            }

        }

        if (oAuthAccessToken != null) {

            request.get(config.endpoint, {
                auth: {
                    bearer: oAuthAccessToken
                }
            }, function(error, response, body) {
                if (!error && response.statusCode == 200) {

                    var user = JSON.parse(response.body);
                    return resolve(user);
                } else {

                    return reject();
                }
            });
        } else {
            return reject();
        }
    });
}

Security.prototype.middlewareHttpBasic = function(config, req, res) {

    if (config === undefined) {
        throw new Error("http basic middleware wasn't configure");
    }

    return new Promise(function(resolve, reject) {
        var reg = new RegExp("^basic ");
        var authorization = req.headers.authorization;
        if (authorization && reg.test(authorization.toLowerCase())) {
            var auth = basic_auth.basic({
                realm: config.realm
            }, function(username, password, callback) { // Custom authentication method.
                callback(username === config.user && password === config.password);
            });

            auth.isAuthenticated(req, function(result) {
                if (result && result.user != undefined) {
                    return resolve({
                        username: result.user
                    });
                } else {
                    return reject();
                }
            })

            // return basic_auth.connect(auth)(req, res, next);
        } else {
            return reject();
        }

    })
}

Security.prototype.getSecurityMiddleware = function(ruleName) {

    var self = this;

    return function(req, res, next) {

        var rule = self.rules[ruleName];

        if (rule == undefined) {
            throw new Error("invalid rule " + ruleName);
        }

        var methods = rule.methods;
        var mode = rule.methodsMode;

        if (mode == undefined) {
            mode = "or";
        }

        if (!_.contains(["or", "and"], mode)) {
            throw new Error("invalid mode '" + mode + "'");
        }

        var middlewares = [];

        _.each(methods, function(key) {
            if (_.isPlainObject(key)) {

                var method = key;
                _.each(_.keys(method), function(k) {
                    var config = self.optionsForMethod[k];

                    middlewares.push({
                        fn: self.validationsForMethod[k],
                        args: [config, req, res]
                    });
                });

            } else {
                var config = self.optionsForMethod[key];
                middlewares.push({
                    fn: self.validationsForMethod[key],
                    args: [config, req, res]
                });
            }
        });


        if (mode == "or") {
            self.handleOrConcurrencyMiddlewares(middlewares, req, res, next);
        } else if (mode == "and") {
            self.handleAndConcurrencyMiddlewares(middlewares, req, res, next);
        }


    }
}

Security.prototype.handleOrConcurrencyMiddlewares = function(middlewares, req, res, next) {
    var self = this;

    var p = _.first(middlewares);
    var promise = p.fn.apply(self, p.args);

    promise.then(function(result) {

        if (req.user != undefined) {
            req.user = _.merge(req.user, result);
        } else {
            req.user = result;
        }

        next();

    }).catch(function(e) {

        middlewares = _.rest(middlewares);
        if (middlewares.length == 0) {
            res.json(401, 'Access denied ');
        } else {
            self.handleOrConcurrencyMiddlewares(middlewares, req, res, next);
        }
    })
}

Security.prototype.handleAndConcurrencyMiddlewares = function(middlewares, req, res, next) {
    var self = this;

    var p = _.first(middlewares);
    var promise = p.fn.apply(self, p.args);

    promise.then(function(result) {

        if (req.user != undefined) {
            req.user = _.merge(req.user, result);
        } else {
            req.user = result;
        }

        middlewares = _.rest(middlewares);

        if (middlewares.length == 0) {
            next();
        } else {
            self.handleAndConcurrencyMiddlewares(middlewares, req, res, next);
        }

    }).catch(function(e) {
        res.json(401, 'Access denied ');
    })
}

Security.prototype.isPromise = function(object) {
    return object === Object(object) && typeof object.then === "function";
}
