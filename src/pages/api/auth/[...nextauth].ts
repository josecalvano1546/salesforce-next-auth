import NextAuth, { NextAuthOptions } from "next-auth";
import SalesforceProvider from 'next-auth/providers/salesforce'

/**
 * Method to check the token expire date by calling the 
 * Salesforce End point fot Token Introspection.
 * @param token 
 */


/**
 * Consume token object and returns a new updated `accessToken`.
 * @param tokenObject 
 */

const salesforceClientId = process.env.SALESFORCE_CLIENT_ID;
const salesforceClientSecret = process.env.SALESFORCE_CLIENT_SECRET;
const salesforceUrlLogin = process.env.SALESFORCE_URL_LOGIN;

if (!salesforceClientId || !salesforceClientSecret || !salesforceUrlLogin) {
    console.log('process.env.SALESFORCE_URL_LOGIN--> ', process.env.SALESFORCE_URL_LOGIN);
    throw new Error('Missing Salesforce environment variables');
}
export const authOptions: NextAuthOptions = {

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
    
    pages: {
        signIn: "/signin",
    }
}

export default NextAuth(authOptions);