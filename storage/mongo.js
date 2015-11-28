var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;
var Promise = require('bluebird');
var bcrypt = require('bcrypt');

/**
 * Mongo implementation of OAuth storage.
 */
var Store = function(logger) {
    this.logger = logger;
    this.mongoose = require('mongoose');
    this.mongoose.connect('mongodb://' + process.env.MONGO_HOST + '/auth', function() {
        var User = new Schema({
            username : String,
            password : String
        });
        var UserModel = this.mongoose.model('User', User);

        var Client = new Schema({
            id : String,
            secret : String
        });

        var ClientModel = this.mongoose.model('Client', Client);
        ClientModel.update(
            {id : 'baseID'},
            {$set: {secret : bcrypt.hashSync('baseSecret', 10)}},
            {upsert:true}, function(err, numAffected) {
                if (err) {
                    this.logger.error(err);
                }
            }.bind(this));


        var Token = new Schema({
            token : String,
            username : String,
            client : String
        });
        var TokenModel = this.mongoose.model('Token', Token);

        /**
         * Creates a user based on username, password.
         * @param username username to create.
         * @param password password to create.
         */
        this.createUser = function(username, password) {
            var deferred = Promise.pending();
            var newUser =  new UserModel();
            newUser.username = username;
            newUser.password = bcrypt.hashSync(password, 10);

            UserModel.find({username:username}, function(err, docs) {
                if (err) {
                    deferred.reject("error checking for existing user");
                } else {
                    if (docs.length > 0) {
                        deferred.reject("Username already in use");
                    } else {
                        newUser.save(function(err, success) {
                            if (err) {
                                deferred.reject("Error creating user " + err);
                            } else {
                                deferred.resolve('User created');
                            }
                        });
                    }
                }

            });

            return deferred.promise;
        };

        /**
         * Validates user password.
         * @param username username of user.
         * @param password password of user.
         * @returns {context.promise|*|promise|promiseAndHandler.promise|PromiseArray.promise|Disposer.promise}
         */
        this.validateUser = function(username, password) {
            var deferred = Promise.pending();
            UserModel.find({username: username}, function (err, docs) {
                if (docs.length == 0) {
                    deferred.reject("No user found");
                } else {
                    var storedPass = docs[0].password;
                    var valid = bcrypt.compareSync(password, storedPass);
                    if (valid) {
                        deferred.resolve("Valid user");
                    } else {
                        deferred.reject("Invalid password");
                    }
                }
            });
            return deferred.promise;
        };

        /**
         * Creates a client.
         * @param id id of client.
         * @param secret secret of client.
         */
        this.createClient = function(id, secret) {
            var baseClient = new ClientModel();
            baseClient.id = id;
            baseClient.secret = bcrypt.hashSync(secret, 10);
            baseClient.save();
        };

        /**
         * Validates existence of client.
         * @param id id of client.
         * @param secret secret of client.
         * @returns {context.promise|*|promise|promiseAndHandler.promise|PromiseArray.promise|Disposer.promise}
         */
        this.validateClient = function(id, secret) {
            var deferred = Promise.pending();
            ClientModel.find({id : id}, function (err, docs) {
                if (docs.length == 0) {
                    deferred.reject("No client found");
                } else {
                    var storedSecret = docs[0].secret;
                    var valid = bcrypt.compareSync(secret, storedSecret);
                    if (valid) {
                        deferred.resolve("Valid client");
                    } else {
                        deferred.reject("Invalid client secret");
                    }
                }
            });
            return deferred.promise;
        };

        /**
         * Determines if current token exists.
         * @param token token to check for.
         * @returns {context.promise|*|promise|promiseAndHandler.promise|PromiseArray.promise|Disposer.promise}
         */
        this.validateToken = function(token) {
            var deferred = Promise.pending();
            TokenModel.find({token : token}, function (err, docs) {
                if (docs.length == 0) {
                    deferred.reject("No token found");
                } else {
                    deferred.resolve(docs[0].username);
                }
            });
            return deferred.promise;
        };

        /**
         * Gets token for authenticated user.
         * @param user user in question.
         */
        this.getToken = function(user, client) {
            var deferred = Promise.pending();
            TokenModel.find({username : user, client: client}, function (err, docs) {
                if (docs.length == 0) {
                    deferred.reject("No token found");
                } else {
                    deferred.resolve(docs[0].token);
                }
            });
            return deferred.promise;
        };

        /**
         * Add a token to our datastore.
         * @param user user that token is for.
         * @param client client that token is for.
         * @param token token itself.
         */
        this.addToken = function(user, client, token) {
            var deferred = Promise.pending();
            var newToken = new TokenModel();
            newToken.token = token;
            newToken.username = user;
            newToken.client = client;
            newToken.save(function(err, success) {
                if (err) {
                    deferred.reject("Error adding token");
                } else {
                    deferred.resolve(token);
                }
            });
            return deferred.promise;
        };
    }.bind(this));
};

module.exports = Store;