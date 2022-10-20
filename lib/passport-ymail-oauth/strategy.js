/**
 * Module dependencies.
 */
const util = require("util");
const OAuth2Strategy = require("passport-oauth").OAuth2Strategy;
const InternalOAuthError = require("passport-oauth").InternalOAuthError;
const crypto = require("crypto");
const querystring = require("querystring");
const https = require("https");
const http = require("http");
const url = require("url");
const fetch = require("node-fetch");
const FormData = require("form-data");

const defaultOptions = {
  authorizationURL: "https://api.login.yahoo.com/oauth2/request_auth",
  tokenURL: "https://api.login.yahoo.com/oauth2/get_token",
  profileURL:
    "https://social.yahooapis.com/v1/user/:xoauthYahooGuid/profile?format=json",
};

class Strategy extends OAuth2Strategy {
  constructor(options = {}, verify) {
    const opts = {
      ...defaultOptions,
      ...options,
    };
    super(opts, verify);
    this._verify = verify;
    this._options = opts;
    this.name = "yahoo";
  }

  async authenticate(req, options = {}) {
    if (req.query && req.query.error) {
      // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
      //       query parameters, and should be propagated to the application.
      return this.fail();
    }

    const callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      const parsed = new URL(callbackURL);
      if (!parsed.protocol) {
        return this.error(
          new InternalOAuthError("callbackURL must be absolute")
        );
      }
    }

    const code = req.query.code;

    if (code) {
      const bearer = Buffer.from(
        this._options.clientID + ":" + this._options.clientSecret
      ).toString("base64");

      const headers = {
        Authorization: `Basic ${bearer}`,
        "Content-Type": "application/x-www-form-urlencoded",
      };
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        redirect_uri: this._options.callbackURL,
        code,
      });

      try {
        const response = await fetch(this._options.tokenURL, {
          headers,
          method: "post",
          body,
        });

        const responseBody = await response.json();

        if (responseBody.error) {
          const message =
            responseBody.error.message || responseBody.error_description;
          return this.error(new InternalOAuthError(message));
        }

        const {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: expiresIn,
        } = responseBody;

        const onVerified = (err, user) => {
          if (err) {
            return this.error(err);
          }
          return this.success(user);
        };

        this._loadUserProfile(
          {
            accessToken: accessToken,
          },
          (err, profile) => {
            if (err) return this.error(err);
            if (this._options.passReqToCallback) {
              this._verify(req, accessToken, refreshToken, profile, onVerified);
            } else {
              this._verify(accessToken, refreshToken, profile, onVerified);
            }
          }
        );
      } catch (err) {
        return this.error(
          new InternalOAuthError("failed to obtain access token", err)
        );
      }
    } else {
      const params = {
        ...this.authorizationParams(options),
        response_type: "code",
        redirect_uri: callbackURL,
      };

      const scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) {
          scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
      }

      if (options.state) {
        params.state = options.state;
      }

      const location = this._oauth2.getAuthorizeUrl(params);

      this.redirect(location);
    }
  }
}

/**
 * Retrieve user profile from Yahoo.
 * inpired from post: http://yahoodevelopers.tumblr.com/post/105969451213/implementing-yahoo-oauth2-authentication
 * other code from : passport-yahoo-token repo
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`
 *   - `displayName`
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = async function (accessToken, done) {
  this._oauth2._useAuthorizationHeaderForGET = true;

  try {
    const response = await fetch(
      `https://api.login.yahoo.com/openid/v1/userinfo`,
      {
        headers: {
          Authorization: this._oauth2.buildAuthHeader(accessToken),
        },
      }
    );
    const { sub, email, email_verified: emailVerified } = await response.json();
    const profile = {
      provider: "yahoo",
      id: sub,
      email,
      emailVerified,
    };
    done(null, profile);
  } catch (err) {
    return done(new InternalOAuthError("Failed to fetch user profile", err));
  }
};

/**
 * User profile
 * @param {Object} params
 * @param {Function} done
 * @private
 */
Strategy.prototype._loadUserProfile = function (params, done) {
  return this.userProfile(params.accessToken, done);
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
