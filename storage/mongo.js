var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;
var Promise = require('bluebird');

/**
 * Mongo implementation of OAuth storage.
 */
var Store = function(logger) {
    this.logger = logger;
    this.mongoose = require('mongoose');
    this.mongoose.connect(process.env.MONGO);

    var User = new Schema({
        username : ObjectId,
        password : String
    });
    var UserModel = this.mongoose.model('User', User);

    var Client = new Schema({
        id : ObjectID,
        secret : String
    });

    var ClientModel = this.mongoose.model('Client', Client);
    ClientModel.update({id : 'baseID', secret : 'baseSecret'}, {upsert: true});

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
        newUser.password = bycrypt.encode(password);
        newUser.save().then(function(success) {
            deferred.resolve('User created');
        }).catch(function(err) {
            deferred.reject("Error creating user " + err);
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
        UserModel.find({password : bcrypt.encode(password), username: username}, function (err, docs) {
            if (docs.length == 0) {
                deferred.reject("No user found");
            } else {
                deferred.resolve("Valid user");
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
        baseClient.secret = bcrypt.encode(secret);
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
        ClientModel.find({id : id, secret: bcrypt.encode(secret)}, function (err, docs) {
            if (docs.length == 0) {
                deferred.reject("No client found");
            } else {
                deferred.resolve("Valid client");
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
        TokenModel.find({username : user, client: client}, function (err, docs) {
            if (docs.length == 0) {
                deferred.reject("No token found");
            } else {
                deferred.resolve(docs[0].token);
            }
        });
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
        newToken.save().then(function(success) {
            deferred.resolve(token);
        }).catch(function(err) {
            deferred.reject("Error adding token");
        });
        return deferred.promise;
    };

};

module.exports = Store;