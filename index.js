import { ServiceBroker } from "moleculer";
import authService from "./services/auth.service.js";
import config from "./moleculer.config.js";
import ApiService from "./services/api.service.js";


const broker = new ServiceBroker({
    ...config,

});

broker.createService(ApiService)
broker.createService(authService);

broker.start().then(() => {
    broker.repl();
    console.log('This project is running on http://localhost:' + process.env.PORT);
});
