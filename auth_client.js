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
     * @param roles list of roles, one user account to be created for each.
     */
    this.registerUser = function(username, password, roles) {
        var self = this;
        //first, register user and create base account, in addition to any role accounts that should be created.
        return this.server.registerUser(username, password, roles)
            .then(function(user) {
                self.user = user;
                //then, authenticate this base application with the base account.
                return this.server.authenticateClient(user.username,
                    user.password, this.CLIENT_NAME, this.CLIENT_SECRET)
            }.bind(this)).then(function(token) {
                self.user.token = token;
                var roles = self.user.accounts;
                var rolePromises = [];
                //next, authenticate the base application with any role accounts.
                roles.map(function(role) {
                    rolePromises.push(this.server.authenticateClient(role.username,
                        role.password, this.CLIENT_NAME, this.CLIENT_SECRET))
                }.bind(this));
                return Promise.all(rolePromises);
            }.bind(this)).then(function() {
                //finally, return user object complete with linked role accounts.
                return self.user;
            }).catch(function(err) {
                return Promise.reject(err);
            });
    };

    /**
     * Logs in a user to Client application.
     * @param username unique username of base product user.
     * @param password password of base product user.
     *
     * Validates user name/password in client_users and returns user object containing userid, username, token, and role.
     */
    this.login = function(username, password) {
        var deferred = Promise.pending();
        this.server.validateUser(username, password)
            .then(function(user) {
                this.server.validateClient(this.CLIENT_NAME, this.CLIENT_SECRET)
                    .then(function(client) {
                        this.server.getToken(user.userid, client.clientid, user.role).then(function(token) {
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
            token : token,
            role : user.role
        }
    }

};

module.exports = AuthClient;

