/**
 * Auth-Starr Client.
 * Implementation of a Client.
 *
 * @param logger for debug messages.  Assumes logger.info and logger.error exist.
 */
var AuthClient =  function(logger, server) {

    this.logger = logger;
    this.server = server;
    this.CLIENT_ID = 'baseID';
    this.CLIENT_SECRET = 'baseSecret';

    /**
     * Registers a user with our base client and authenticates it.
     * @param user user to be created.
     * @param password password of user.
     */
    this.registerUser = function(user, password) {
        return this.server.registerUser(user, password)
            .then(function(success) {
                return this.server.authenticateClient(user, password, this.CLIENT_ID, this.CLIENT_SECRET)
            }.bind(this));
    };

    /**
     * Logs in a user to Client application.
     * @param user unique username of base product user.
     * @param password password of base product user.
     *
     * Validates user name/password in client_users and returns stored auth token from client_tokens.
     */
    this.login = function(user, password) {
        return this.server.validateUser(user, password)
            .then(function(success) {
                return this.server.getToken(user, this.CLIENT_ID)
            }.bind(this));
    };

};

module.exports = AuthClient;

