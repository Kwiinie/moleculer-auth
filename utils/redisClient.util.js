import { createClient } from "redis";

const getRedisClient = async () => {

    let password = "", host = "", port = -1, client = null;
    try {
        console.log(process.env.REDIS_PASSWORD, process.env.REDIS_PORT, process.env.REDIS_URL)
        password = process.env.REDIS_PASSWORD;
        host = process.env.REDIS_URL;
        port = parseInt(process.env.REDIS_PORT);
        if (Number.isNaN(port)) throw new Error("Invalid PORT")
        client = createClient({
            password: password,
            socket: {
                host: host,
                port: port
            }
        }).on('error', err => console.log('Redis Client Error', err));
        await client.connect();

    } catch (error) {
        console.log(error)
    }
    return client;
}

export default getRedisClient;