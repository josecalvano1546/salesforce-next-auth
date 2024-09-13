import type { NextApiRequest, NextApiResponse } from 'next'
import jsforce from "jsforce"
import { getToken } from 'next-auth/jwt'

/* export const getSFDCConnection = async (req: NextApiRequest, res: NextApiResponse) => {
    try {
        const jwt = await getToken({ req })
        console.log('JWT -> ', jwt);

        if (!jwt) {
            res.status(401).json({ message: 'Unauthorized!' });
            return;
        }

        return await new jsforce.Connection({
            // @ts-ignored
            instanceUrl: jwt.instanceUrl,
            // @ts-ignored
            accessToken: jwt.accessToken,
            
        });
    } catch (error) {
        return { error: 'SFDCConnectionError' }
    }
}  */

    export const getSFDCConnection = async (req: NextApiRequest, res: NextApiResponse) => {
        try {
            // Obtener el token JWT de la sesión
            const jwt = await getToken({ req });
            console.log('JWT -> ', jwt);
    
            // Verificar si no hay token, devolver error 401
            if (!jwt) {
                res.status(401).json({ message: 'Unauthorized!' });
                return;
            }
    
            // Crear una instancia de conexión a Salesforce con los tokens
            const conn = new jsforce.Connection({
                oauth2: {
                    clientId: process.env.SALESFORCE_CLIENT_ID,
                    clientSecret: process.env.SALESFORCE_CLIENT_SECRET,
                    redirectUri: process.env.SALESFORCE_URL_LOGIN,
                },
                // @ts-ignored
                instanceUrl: jwt.instanceUrl,
                // @ts-ignored
                accessToken: jwt.accessToken,
                // @ts-ignored
                refreshToken: jwt.refreshToken, // Asegúrate de pasar el refresh token
            });
    
            // Listener para refrescar el accessToken cuando expire
            conn.on("refresh", (accessToken) => {
                console.log('Token refreshed:', accessToken);
                // Aquí podrías guardar el nuevo accessToken en la sesión o en algún almacenamiento.
                // Por ejemplo, podrías actualizar la sesión de NextAuth si fuera necesario.
            });
    
            // Retornar la conexión para usarla en otras partes
            return conn;
        } catch (error) {
            console.error('SFDCConnectionError:', error);
            res.status(500).json({ error: 'SFDCConnectionError' });
        }
    };


/* const conn = new jsforce.Connection({
    oauth2 : {
      clientId : '<your Salesforce OAuth2 client ID is here>',
      clientSecret : '<your Salesforce OAuth2 client secret is here>',
      redirectUri : '<your Salesforce OAuth2 redirect URI is here>'
    },
    instanceUrl : '<your Salesforce server URL (e.g. https://na1.salesforce.com) is here>',
    accessToken : '<your Salesforce OAuth2 access token is here>',
    refreshToken : '<your Salesforce OAuth2 refresh token is here>'
  });
  conn.on("refresh", (accessToken, res) => {
    // Refresh event will be fired when renewed access token
    // to store it in your storage for next request
  }); */