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
            password : String,
            userid : Number,
            role : String
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
            clientid : String,
            role : String
        });
        var TokenModel = this.mongoose.model('Token', Token);

        /**
         * Creates a user based on username, password.
         * @param username username to create.
         * @param password password to create.
         * @param roles, one user account to be created for each role.
         * @return new user object.
         */
        this.createUsers = function(username, password, roles) {
            var deferred = Promise.pending();
            var newUser =  new UserModel();
            //create base client user object.
            newUser.role = 'client';
            newUser.username = username;
            newUser.password = bcrypt.hashSync(password, 10);
            //make sure that this username doesn't exist already
            UserModel.find({username:username}, function(err, docs) {
                if (err) {
                    deferred.reject("error checking for existing user");
                } else {
                    if (docs.length > 0) {
                        deferred.reject("Username already in use");
                    } else {
                        //get next valid user id for user account.
                        this.getNextUserId().then(function(highest) {
                            newUser.userid = highest;
                            newUser.save(function(err) {
                                if (err) {
                                    deferred.reject("Error creating user " + err);
                                } else {
                                    newUser.password = password;
                                    //strip any mongo fields from user object
                                    var userObject = this.generateUserObject(newUser, true);
                                    //add our accounts field including our role accounts to the user object.
                                    deferred.resolve(this.createAccountRoles(userObject, roles, highest, username));
                                }
                            }.bind(this));
                        }.bind(this)).catch(function(error) {
                            deferred.resolve("Error calculating user id: " + error);
                        });
                    }
                }

            }.bind(this));

            return deferred.promise;
        };

        /**
         * Creates list of user account objects to return on user creation.
         * @param user user object that is basis of account.
         * @param roles roles, one account is created for each.
         * @param userid userid of base account.
         * @param username username of base account.
         * @returns {*}
         */
        this.createAccountRoles = function(user, roles, userid, username) {
            var deferred = Promise.pending();
            var rolesList = [];
            var rolesPromises = [];
            roles.map(function(role) {
                rolesPromises.push(this.createRole(role, userid, username));
            }.bind(this));
            Promise.all(rolesPromises).then(function(role_users) {
                role_users.map(function(role_user) {
                    rolesList.push(role_user);
                });
                user.accounts = rolesList;
                deferred.resolve(user);
            }.bind(this));
            return deferred.promise;
        };

        /**
         * Creates a role account for the given role.
         * @param role the role being created.
         * @param id id of the account that the role is being created for.
         * @param username username of the base account that the role is being created for.
         * @returns {*|promise}
         */
        this.createRole = function(role, id, username) {
            var deferred = Promise.pending();
            var newUser =  new UserModel();
            newUser.role = role;
            newUser.username = this.generateRoleUsername(username, role);
            var password = this.generateRandomPassword();
            newUser.password = bcrypt.hashSync(password, 10);
            UserModel.find({username:newUser.username}, function(err, docs) {
                if (err) {
                    deferred.reject("error checking for existing user");
                } else {
                    if (docs.length > 0) {
                        deferred.reject("Username already in use");
                    } else {
                        newUser.userid = id;
                        newUser.save(function(err, success) {
                            if (err) {
                                deferred.reject("Error creating user " + err);
                            } else {
                                //send back unencrypted role password first time.
                                newUser.password = password;
                                deferred.resolve(this.generateUserObject(newUser, true));
                            }
                        }.bind(this));
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
         * @param id id of client.
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
                    var role = docs[0].role;
                    var token = docs[0].token;
                    deferred.resolve({
                        userid : userid,
                        token : token,
                        role : role
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
        this.getToken = function(userid, clientid, role) {
            var deferred = Promise.pending();
            TokenModel.find({userid : userid, clientid: clientid, role: role}, function (err, docs) {
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
         * @param role identifying role that token is for.
         * @param token token itself.
         */
        this.addToken = function(userid, clientid, role, token) {
            var deferred = Promise.pending();
            var newToken = new TokenModel();
            newToken.token = token;
            newToken.userid = userid;
            newToken.role = role;
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

        /**
         * Creates user object by removing object ids and optionally password.
         * @param obj obj to create user object out of.
         * @param includePassword boolean indicating whether to include password in response.
         */
        this.generateUserObject = function(obj, includePassword) {
            var userObj = {
                userid : obj.userid,
                username : obj.username,
                role : obj.role
            };
            if (includePassword) {
                userObj.password = obj.password;
            };
            return userObj
        };

        /**
         * Generates
         * @param username
         * @returns {string}
         */
        this.generateRoleUsername = function(username, role) {
            //TODO figure out the actual structure of returned response that we need.
            if (username.indexOf('@') != -1) {
                username = username.substring(0, username.indexOf('@'));
            }
            return username + '_' + role;
        };

        /**
         * Generates random 5 character user password.
         */
        this.generateRandomPassword = function() {
            return Math.random().toString(36).substr(2, 7);
        };

    }.bind(this));
};

module.exports = Store;