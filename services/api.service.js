"use strict";

import ApiGateway from "moleculer-web";

const ApiService = {
    name: "api",
    mixins: [ApiGateway],
    settings: {
        port: process.env.PORT,
        ip: "0.0.0.0",
        
        routes: [
            {
                path: "/api",

                whitelist: [
                    "**"
                ],
                mergeParams: true,
                authentication: false,
                authorization: false,
                autoAliases: true,

                onBeforeCall(ctx, route, req, res) {
                    ctx.meta.clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;
                    console.log("Client IP:", ctx.meta.clientIp);
                },


                aliases: {

                },
                callOptions: {},

                bodyParsers: {
                    json: {
                        strict: true,
                        limit: "1MB"
                    },
                    urlencoded: {
                        extended: true,
                        limit: "1MB"
                    }
                },
                mappingPolicy: "all",
                logging: true
            }
        ],
        log4XXResponses: false,
        logRequestParams: true,
        logResponseData: true,

    },
};

export default ApiService;
