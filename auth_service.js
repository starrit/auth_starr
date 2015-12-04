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
     * Checks token to ensure that request is valid.
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
            }).catch(function(error) {
                res.status(401).json("Authentication failure");
            })
        }
    }.bind(this);

    /**
     * Creates a user in our system.
     * @param user unique username of base product user.
     * @param password password of base product user.
     */
    this.registerUser = function(user, password) {
        return this.mongo.createUser(user, password);
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
     */
    this.authenticateClient = function(username, password, client_name, client_secret) {
        var deferred = Promise.pending();
        this.mongo.validateUser(username, password)
            .then(function(user) {
                this.mongo.validateClient(client_name, client_secret).then(function (client) {
                    this.mongo.addToken(user.userid, client.clientid, this.createToken()).then(function(token) {
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
     */
    this.getToken = function(userid, clientid) {
        return this.mongo.getToken(userid, clientid);
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

