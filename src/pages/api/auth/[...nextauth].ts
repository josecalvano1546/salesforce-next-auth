import NextAuth, { NextAuthOptions } from "next-auth";
import SalesforceProvider from 'next-auth/providers/salesforce'
import axios from 'axios'
import qs from 'qs'

/**
 * Method to check the token expire date by calling the 
 * Salesforce End point fot Token Introspection.
 * @param token 
 */
const tokenIntrospection = async (tokenObject: any) => {
    try {
        var data = qs.stringify({
            'token': tokenObject.accessToken,
            'token_type_hint': 'access_token',
            'client_id': process.env.SALESFORCE_CLIENT_ID,
            'client_secret': process.env.SALESFORCE_CLIENT_SECRET
        });

        const tokenResponse = await axios({
            method: 'post',
            url: `https://login.salesforce.com/services/oauth2/introspect`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            data: data
        });

        return await tokenResponse.data;
    } catch (error) {
        return {
            error: "TokenIntrospectionError",
        }
    }
}

/**
 * Consume token object and returns a new updated `accessToken`.
 * @param tokenObject 
 */
const refreshAccessToken = async (tokenObject: any) => {
    try {
        var data = qs.stringify({
            'grant_type': 'refresh_token',
            'client_id': process.env.SALESFORCE_CLIENT_ID,
            'client_secret': process.env.SALESFORCE_CLIENT_SECRET,
            'refresh_token': tokenObject.refreshToken
        });

        const tokenResponse = await axios({
            method: 'post',
            url: `https://login.salesforce.com/services/oauth2/token`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: data
        });

        const { access_token, refresh_token, instance_url } = await tokenResponse.data;

        // Get expire date from token introspection end point.
        tokenObject.accessToken = access_token;
        const { exp } = await tokenIntrospection(tokenObject);

        return {
            accessToken: access_token,
            refreshToken: refresh_token ?? tokenObject.refreshToken,
            accessTokenExpires: exp,
            instanceUrl: instance_url
        };
    } catch (error) {
        return {
            error: "RefreshAccessTokenError",
        }
    }
}

const salesforceClientId = process.env.SALESFORCE_CLIENT_ID;
const salesforceClientSecret = process.env.SALESFORCE_CLIENT_SECRET;
const salesforceUrlLogin = process.env.SALESFORCE_URL_LOGIN;

if (!salesforceClientId || !salesforceClientSecret || !salesforceUrlLogin) {
    console.log('process.env.SALESFORCE_URL_LOGIN--> ', process.env.SALESFORCE_URL_LOGIN);
    throw new Error('Missing Salesforce environment variables');
}

const cookiePrefix = '__Secure-';
export const authOptions: NextAuthOptions = {
    callbacks: {
        async jwt({ token, account }) {
            console.log('account -> ', account);
            // Initial sign in
            if (account) {
                // Set access and refresh token
                token.accessToken = account.access_token;
                token.refreshToken = account.refresh_token;
                token.instanceUrl = account.instance_url;

                // Get the Expire Date
                const { exp } = await tokenIntrospection(token);
                token.accessTokenExpires = exp;

                console.log('Use New Token...');
                return Promise.resolve(token);
            }

            console.log('token.accessTokenExpires -> ', token.accessTokenExpires);

            // @ts-ignored
            if (Date.now() < (token.accessTokenExpires * 100)) {
                console.log('Use Previous Token...');
                return Promise.resolve(token);
            } 

            console.log('Use Refresh Token...');
            return Promise.resolve(await refreshAccessToken(token));
        }
    },

    providers: [
        SalesforceProvider({
            name: 'Salesforce',
            clientId: salesforceClientId,
            clientSecret: salesforceClientSecret,
            idToken: true,
            wellKnown: `https://login.salesforce.com/.well-known/openid-configuration`,
            authorization: { params: { scope: 'openid api refresh_token' } },
            userinfo: {
                async request({ provider, tokens, client }) {
                    //@ts-ignored
                    return await client.userinfo(tokens, {
                        //@ts-ignored
                        params: provider.userinfo?.params,
                    });
                },
            },
            profile(profile) {
                return { id: profile.email, ...profile };
            }
        })
    ], 
    cookies: {
        sessionToken: {
          name: `__Secure-next-auth.session-token`,
          options: {
            httpOnly: true,
            sameSite: 'none',
            path: '/',
            secure: true
          }
        },
        callbackUrl: {
          name: `__Secure-next-auth.callback-url`,
          options: {
            sameSite: 'none',
            path: '/',
            secure: true
          }
        },
        csrfToken: {
          name: `__Host-next-auth.csrf-token`,
          options: {
            httpOnly: true,
            sameSite: 'none',
            path: '/',
            secure: true
          }
        },
        pkceCodeVerifier: {
          name: `${cookiePrefix}next-auth.pkce.code_verifier`,
          options: {
            httpOnly: true,
            sameSite: 'none',
            path: '/',
            secure: true,
            maxAge: 900
          }
        },
        state: {
          name: `${cookiePrefix}next-auth.state`,
          options: {
            httpOnly: true,
            sameSite: "none",
            path: "/",
            secure: true,
            maxAge: 900
          },
        },
        nonce: {
          name: `${cookiePrefix}next-auth.nonce`,
          options: {
            httpOnly: true,
            sameSite: "none",
            path: "/",
            secure: true,
          },
        },
      },
    
    pages: {
        signIn: "/signin",
    }
}

export default NextAuth(authOptions);