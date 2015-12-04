var mongoose = require('mongoose');
var Schema = mongoose.Schema;
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
            password : String,
            userid : Number
        });
        var UserModel = this.mongoose.model('User', User);

        var Client = new Schema({
            clientid : Number,
            secret : String,
            name : String
        });

        var ClientModel = this.mongoose.model('Client', Client);
        ClientModel.update(
            {name : 'baseID'},
            {$set: {secret : bcrypt.hashSync('baseSecret', 10), clientid : 43}},
            {upsert:true}, function(err, numAffected) {
                if (err) {
                    this.logger.error(err);
                }
            }.bind(this));


        var Token = new Schema({
            token : String,
            userid : String,
            clientid : String
        });
        var TokenModel = this.mongoose.model('Token', Token);

        /**
         * Creates a user based on username, password.
         * @param username username to create.
         * @param password password to create.
         * @return new user object.
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
                        this.getNextUserId().then(function(highest) {
                            newUser.userid = highest;
                            newUser.save(function(err, success) {
                                if (err) {
                                    deferred.reject("Error creating user " + err);
                                } else {
                                    deferred.resolve(newUser);
                                }
                            });
                        }).catch(function(error) {
                            deferred.resolve("Error calculating user id: " + error);
                        });
                    }
                }

            }.bind(this));

            return deferred.promise;
        };

        /**
         * Gets next available user id in system.
         * @returns {*}
         */
        this.getNextUserId = function() {
            var deferred = Promise.pending();
            UserModel.find({$query:{},$orderby:{userid:-1}}, function(err, docs) {
                if (err) {
                    deferred.reject("Error obtaining next user id " + err);
                } else {
                    if (docs.length == 0) {
                        deferred.resolve(111);
                    } else {
                        var highest = docs[0].userid;
                        deferred.resolve(highest + 1);
                    }
                }
            });
            return deferred.promise;
        };

        /**
         * Gets next available client id in system.
         * @returns {*}
         */
        this.getNextClientId = function() {
            var deferred = Promise.pending();
            ClientModel.find({$query:{},$orderby:{userid:-1}}, function(err, docs) {
                if (err) {
                    deferred.reject("Error obtaining next client id " + err);
                } else {
                    if (docs.length == 0) {
                        deferred.resolve(43);
                    } else {
                        var highest = docs[0].clientid;
                        deferred.resolve(highest + 1);
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
                if (err) {
                    deferred.reject(err);
                } else {
                    if (docs.length == 0) {
                        deferred.reject("No user found");
                    } else {
                        var storedPass = docs[0].password;
                        var valid = bcrypt.compareSync(password, storedPass);
                        if (valid) {
                            deferred.resolve(docs[0]);
                        } else {
                            deferred.reject("Invalid password");
                        }
                    }
                }
            });
            return deferred.promise;
        };

        /**
         * Creates a client.
         * @param name name of client.
         * @param secret secret of client.
         */
        this.createClient = function(name, secret) {
            var baseClient = new ClientModel();
            baseClient.name = id;
            baseClient.secret = bcrypt.hashSync(secret, 10);
            this.getNextClientId().then(function(highest) {
                baseClient.clientid = highest;
                baseClient.save();
            }).catch(function(error) {
                this.logger.error("Error creating client " + error);
            }.bind(this));
        };

        /**
         * Validates existence of client.
         * @param name name of client.
         * @param secret secret of client.
         * @returns {context.promise|*|promise|promiseAndHandler.promise|PromiseArray.promise|Disposer.promise}
         */
        this.validateClient = function(name, secret) {
            var deferred = Promise.pending();
            ClientModel.find({name : name}, function (err, docs) {
                if (docs.length == 0) {
                    deferred.reject("No client found");
                } else {
                    var storedSecret = docs[0].secret;
                    var valid = bcrypt.compareSync(secret, storedSecret);
                    if (valid) {
                        deferred.resolve(docs[0]);
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
                    var userid = docs[0].userid;
                    var token = docs[0].token;
                    deferred.resolve({
                        userid : userid,
                        token : token
                    });
                }
            });
            return deferred.promise;
        };

        /**
         * Gets token for authenticated user.
         * @param userid user in question.
         * @param clientid id of client in question.
         */
        this.getToken = function(userid, clientid) {
            var deferred = Promise.pending();
            TokenModel.find({userid : userid, clientid: clientid}, function (err, docs) {
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
         * @param userid user that token is for.
         * @param clientid client that token is for.
         * @param token token itself.
         */
        this.addToken = function(userid, clientid, token) {
            var deferred = Promise.pending();
            var newToken = new TokenModel();
            newToken.token = token;
            newToken.userid = userid;
            newToken.clientid = clientid;
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