var Promise = require('bluebird');
var storage = require('./storage/mongo');

/**
 * Auth-Starr Service.
 * Base service refers to the service with which users have accounts/passwords.
 * Client service is that requesting to make api request on behalf of the user.
 *
 * @param logger for debug messages.  Assumes logger.info and logger.error exist.
 */
var AuthService =  function(logger) {

    this.logger = logger;
    this.mongo = new storage(logger);

    /**
     * Returns a function that can serve as a middleware component, validating not
     * only that an auth token is valid but that it has one of the roles defined by
     * an input list of predefined roles.
     *
     */
    this.validateRole = function(roles) {
        return function(req, res, next) {
            var token = req.query.token;
            if (!token) {
                res.status(400).json("Authentication failure, missing token");
            } else {
                this.mongo.validateToken(token).then(function(user) {
                    var userRole = user.role;
                    if (roles.indexOf(userRole) == -1) {
                        res.status(403).json("User not authorized to access this endpoint");
                    } else {
                        req.user = user;
                        next();
                    }
                }).catch(function() {
                    res.status(401).json("Authentication failure");
                })
            }
        }.bind(this);
    };

    /**
     * Middleware that checks token to ensure that request is valid, only checking that a user exists for given token.
     * @param req request object.
     * @param res response object.
     * @param next to be called on completion.
     *
     * Checks the user_tokens collection to ensure token is valid.
     */
    this.validate = function(req, res, next) {
        var token = req.query.token;
        if (!token) {
            res.status(400).json("Authentication failure, missing token");
        } else {
            this.mongo.validateToken(token).then(function(user) {
                req.user = user;
                next();
            }).catch(function() {
                res.status(401).json("Authentication failure");
            });
        }
    }.bind(this);

    /**
     * Direct method call that checks token to ensure that request is valid, only checking that a user exists for given token.
     * @param token to validate.
     *
     * Checks the user_tokens collection to ensure token is valid and returns a Promise object.
     */
    this.validateToken = function(token) {
        var deferred = Promise.pending();
        if (!token) {
            deferred.reject("Unable to find token to validate");
        } else {
            this.mongo.validateToken(token).then(function(user) {
                deferred.resolve(user);
            }).catch(function() {
                deferred.reject("Invalid user");
            });
        }
        return deferred.promise;
    };

    /**
     * Creates a user in our system.
     * @param user unique username of base product user.
     * @param password password of base product user.
     * @param roles list of roles users should be created for.
     */
    this.registerUser = function(user, password, roles) {
        return this.mongo.createUser(user, password, roles);
    };

    /**
     * Registers a client.
     * @param name name of client.
     * @param secret secret of client.
     * @returns {*}
     */
    this.registerClient = function(name, secret) {
        return this.mongo.createClient(name, secret);
    };

    /**
     * Authenticates Client for registered User.
     * Creates token for each role associated with this user.
     * @param username username of base product user.
     * @param password of base product user.
     * @param client_name name of Client requesting access.
     * @param client_secret of Client requesting access.
     *
     * Verifies client id/secret in our client collection.
     * Verifies user/password combination.
     *
     * Creates an entry in our tokens collection.
     *  {
     *      userid:<user>,
     *      clientid:<client>,
     *      token:<token>
     *  }
     *  @return the token that was created.
     */
    this.authenticateClient = function(username, password, client_name, client_secret) {
        var deferred = Promise.pending();
        this.mongo.validateUser(username, password)
            .then(function(user) {
                this.mongo.validateClient(client_name, client_secret).then(function (client) {
                    this.mongo.addToken(user.userid, client.clientid, user.role, this.createToken()).then(function(token) {
                        deferred.resolve(token);
                    });
                }.bind(this))
            }.bind(this)).catch(function(error) {
                deferred.reject(error);
            });
        return deferred.promise;
    };

    /**
     * Validate user for base application.
     * @param user username in base application.
     * @param password password in base application.
     * @returns {*}
     */
    this.validateUser = function(user, password) {
        return this.mongo.validateUser(user, password);
    };

    /**
     * Validate client for base application.
     * @param client_name name of client.
     * @param client_password password of client.
     * @returns {context.promise|*|promise|promiseAndHandler.promise|PromiseArray.promise|Disposer.promise}
     */
    this.validateClient = function(client_name, client_password) {
        return this.mongo.validateClient(client_name, client_password);
    };

    /**
     * Returns token for client - only occurs if token already exists in datastore,
     * meaning user has authenticated client for use.
     * @param userid base application username.
     * @param clientid client requesting token.
     * @param role the role of the account requesting access.
     */
    this.getToken = function(userid, clientid, role) {
        return this.mongo.getToken(userid, clientid, role);
    };


    /**
     * Creates a random token;
     * @returns {string}
     */
    this.createToken = function() {
        return Math.random().toString(36).substr(2);
    }
};

module.exports = AuthService;

