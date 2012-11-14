/**
 * Module dependencies.
 */
var util = require('util'), 
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy, 
    InternalOAuthError = require('passport-oauth').InternalOAuthError;

var authic_domain = "";

/**
 * Setup for Authic Authentication
 *
 * clientId - your Authic client key
 * clientSecret - your Authic client secret
 * callbackUrl - tell Authic where to call back to in your app e.g. 'https://localhost:3000/auth/authic/callback'
 * subdomain - the Authic subdomain on which you are running your authenitcation service e.g. 'myapp'
 * 
 * All those options are mandatory
 */
function Strategy(options, verify) {
  options = options || {};
  authic_domain = 'https://' + options.subdomain + '.authic.com';
  options.authorizationURL = options.authorizationURL || authic_domain + '/oauth/authorize';
  options.tokenURL = options.tokenURL || authic_domain + '/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'authic';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Grab the User profile data from Authic after a successful token exchange
 * 
 * TODO: List detailed data structure
 */
Strategy.prototype.userProfile = function(accessToken, done) {
	
  var user_info_url = authic_domain + '/authic_user_info.json';
	
  this._oauth2.getProtectedResource(user_info_url, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'authic' };
      profile.id = json.id;
      profile.username = json.email;
      profile.displayName = json.full_name;
      profile.name = { familyName: json.last_name,
                       givenName: json.first_name,
                       middleName: json.middle_name };
      profile.gender = json.gender;
      profile.profileUrl = json.link;
      profile.emails = [{ value: json.email }];
      
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;