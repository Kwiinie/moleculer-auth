"use strict"
import fs from 'fs';
import DbService from 'moleculer-db';
import MongoDbAdapter from 'moleculer-db-adapter-mongo';
import dotenv from "dotenv";
dotenv.config();

export default function (collection) {
    const cacheCleanEventName = `cache.clean.${collection}`;

    /** @type {MoleculerDB & ServiceSchema} */
    const schema = {
        mixins: [DbService],
        settings: {
            fields: ["_id", "createdAt", "updatedAt"],
            entityValidator: {
                _id: { type: "string", objectId: true, optional: true },
                createdAt: { type: "date", optional: true },
                updatedAt: { type: "date", optional: true }
            }
        },
        hooks: {
            before: {
                async register(ctx) {
                    ctx.params.createdAt = new Date();
                    ctx.params.updatedAt = new Date();
                },
                async update(ctx) {
                    ctx.params.updatedAt = new Date();
                }
            }
        },

        events: {
            /**
             * Subscribe to the cache clean event. If it's triggered
             * clean the cache entries for this service.
             *
             * @param {Context} ctx
             */
            async [cacheCleanEventName]() {
                if (this.broker.cacher) {
                    await this.broker.cacher.clean(`${this.fullName}.*`);
                }
            }
        },

        methods: {
            /**
             * Send a cache clearing event when an entity changed.
             *
             * @param {String} type
             * @param {any} json
             * @param {Context} ctx
             */
            async entityChanged(type, json, ctx) {
                ctx.broadcast(cacheCleanEventName);
            }
        },

        async started() {

        }
    };

    if (process.env.MONGODB_URL) {
        schema.adapter = new MongoDbAdapter(process.env.MONGODB_URL);
        schema.collection = collection;
        console.log("MONGODB_URL: " + process.env.MONGODB_URL);
    } else if (process.env.NODE_ENV === 'test') {
        // NeDB memory adapter for testing
        schema.adapter = new DbService.MemoryAdapter();
    } else {
        // NeDB file DB adapter
        // Create data folder
        if (!fs.existsSync("./data")) {
            fs.mkdirSync("./data");
        }

        schema.adapter = new DbService.MemoryAdapter({ filename: `./data/${collection}.db` });
    }

    return schema;
}

