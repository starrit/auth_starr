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
     * @param token to be validated.
     *
     * Checks the user_tokens collection to ensure token is valid.
     */
    this.validate = function(req, res, next) {
        var token = req.query.token;
        if (!token) {
            res.status(400).json("Authentication failure, missing token");
        } else {
            this.mongo.validateToken(token).then(function(userid) {
                req.query.user = userid;
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
     *
     * Creates an entry in our users collection.
     */
    this.registerUser = function(user, password) {
        return this.mongo.createUser(user, password);
    };

    /**
     * Registers a client.
     * @param id id of client.
     * @param secret secret of client.
     * @returns {*}
     */
    this.registerClient = function(id, secret) {
        return this.mongo.createClient(id, secret);
    };

    /**
     * Authenticates Client for registered User.
     * @param user username of base product user.
     * @param password of base product user.
     * @param client_id id of Client requesting access.
     * @param client_secret of Client requesting access.
     *
     * Verifies client id/secret in our client collection.
     * Verifies user/password combination.
     *
     * Creates an entry in our tokens collection.
     *  {
     *      user:<user>,
     *      client:<client>,
     *      token:<token>
     *  }
     */
    this.authenticateClient = function(user, password, client_id, client_secret) {
        return this.mongo.validateUser(user, password)
            .then(function() {return this.mongo.validateClient(client_id, client_secret)}.bind(this))
            .then(function() {return this.mongo.addToken(user, client_id, this.createToken())}.bind(this))
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
     * Returns token for client - only occurs if token already exists in datastore,
     * meaning user has authenticated client for use.
     * @param user base application username.
     * @param client client requesting token.
     */
    this.getToken = function(user, client) {
        return this.mongo.getToken(user, client);
    }


    /**
     * Creates a random token;
     * @returns {string}
     */
    this.createToken = function() {
        return Math.random().toString(36).substr(2);
    }
};

module.exports = AuthService;

