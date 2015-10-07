Simple OAuth Module
====================

First implementation based on MongoDB, assumes availability of MONGO_HOST variable in the .env file in the project utilizing the library.
Two classes are available for use, one being a typical oauth API for allowing third parties to authenticate as users. The
second is a client class built with the intention of representing the 'main application', in most cases built by the same
party as the API, so that it can use the same OAuth method of authentication as third parties.  Some of the methods
such as login, creating users, are passthroughs from the auth_client to the auth_service, give the data should be one and the same.

Require
=====================
In your index.js file, include the following to add this OAuth service.  Logger being a logger object of your choice,
with the .error and .info methods being expected to be available.

var authLibrary = require('@starrit/auth_starr');
var authService = new authLibrary.auth_service(logger);
var authClient = new authLibrary.auth_client(logger, authServer);


Registering User
====================
You will have to register users of your API/base application so that the OAuth library can authenticate against them.
Use the following command to do so.

authService.registerUser(username, password)

This will return a Promise object, and will fail if the username is already in use.

Authenticating
=====================
When you are want to authenticate a third party to login as a user, you have the below command available to you:

authService.authenticateClient(username, password, client_id, client_secret)

This method returns a Promise object containing a valid token to be used in future API calls,
and will persist knowledge that the given client is authenticated for given user in the form of this token.
Checks are done to validate the user credentials and the client id/secret.

Obtaining a Token/Login
=====================
When a user logs in in a future instance, the OAuth service takes the client id and user name and is able to return
a pre-fetched token for use on API calls.  Use the following method to do so.

authService.getToken(username, client_id).

This method returns a Promise object resolving to include the token.

Client Class : Registering a User
=====================
For ease of implementation, 2 methods are available on the authClient that can be used if the same application is
also running a client.  The first will register a user, and also authenticate the application, returning a token.

authClient.registerUser(username, password)

This will return a Promise object resolving to a valid token.  The authClient class has knowledge of its client id
and secret, so these details are not needed.

Client Class : Login
=====================
In the case where the client and api are run by the same service, logging into the client also serves the purpose
of authenticating with the API.  To do so use the following command.

authClient.login(username, password)

This will return a Promise object resolving to a valid token.
