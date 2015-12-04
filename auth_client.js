var Promise = require('bluebird');

/**
 * Auth-Starr Client.
 * Implementation of a Client.
 *
 * @param logger for debug messages.  Assumes logger.info and logger.error exist.
 */
var AuthClient =  function(logger, server) {

    this.logger = logger;
    this.server = server;
    this.CLIENT_NAME = 'baseID';
    this.CLIENT_SECRET = 'baseSecret';

    /**
     * Registers a user with our base client and authenticates it.
     * @param username username of user to be created.
     * @param password password of user.
     */
    this.registerUser = function(username, password) {
        return this.server.registerUser(username, password)
            .then(function(user) {
                return this.server.authenticateClient(username, password, this.CLIENT_NAME, this.CLIENT_SECRET)
                    .then(function(token) {
                        return this.createUserResponse(user, token);
                    }.bind(this))

            }.bind(this));
    };

    /**
     * Logs in a user to Client application.
     * @param username unique username of base product user.
     * @param password password of base product user.
     *
     * Validates user name/password in client_users and returns user object containing userid, username, token.
     */
    this.login = function(username, password) {
        var deferred = Promise.pending();
        this.server.validateUser(username, password)
            .then(function(user) {
                this.server.validateClient(this.CLIENT_NAME, this.CLIENT_SECRET)
                    .then(function(client) {
                        this.server.getToken(user.userid, client.clientid).then(function(token) {
                            deferred.resolve(this.createUserResponse(user, token));
                        }.bind(this));
                    }.bind(this));
            }.bind(this)).catch(function(err) {
                deferred.reject(err);
            });
        return deferred.promise;
    };

    /**
     * Returns a friendly version of our user object, including current token without any object ids.
     * @param user user object containing user information.
     * @param token token nfor the user.
     * @returns {{userid: (*|userid), username: *, token: *}}
     */
    this.createUserResponse = function(user, token) {
        return {
            userid : user.userid,
            username : user.username,
            token : token
        }
    }

};

module.exports = AuthClient;

