"use strict";
import dbMixin from "../mixins/db.mixin.js";
import bcrypt from "bcryptjs";
import getRedisClient from "../utils/redisClient.util.js";
import { Errors } from "moleculer";

const authService = {
    name: "auth",
    mixins: dbMixin("users"),

    settings: {
        fields: ["_id", "username", "password"],
        entityValidator: {
            username: { type: "string", unique: true },
            password: { type: "string" },
        }
    },
    methods: {
        generateOTP() {
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let otp = '';
            for (let i = 0; i < 6; i++) {
                const randomIndex = Math.floor(Math.random() * characters.length);
                otp += characters[randomIndex];
            }
            return otp;
        }
    },

    actions: {
        register: {
            rest: "POST /register",
            params: {
                username: { type: "string", pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$", required: true },
                password: { type: "string", required: true },
                otp: { type: "string", optional: true }
            },
            async handler(ctx) {
                const { username, password } = ctx.params;
                const checkUser = await this.adapter.findOne({ username: username });

                //check if the user exists
                if (checkUser) {
                    throw new Error("User already exists");
                } else {
                    const hash = await bcrypt.hash(password, 10);
                    const user = { username, password: hash, createdAt: new Date(), updatedAt: new Date() };
                    //create key in redis
                    const client = await getRedisClient();
                    const ipAddress = ctx.meta.clientIp;
                    const key = `register:${ipAddress}`;
                    const requestsMade = await client.incr(key);

                    //more than 3 requests, request otp
                    if (requestsMade > 3) {
                        const otp = ctx.params.otp;
                        console.log("ipAddress: ", ipAddress);
                        const otpKey = await client.hGet(`register:otp:${ipAddress}`, 'otp');
                        console.log("checkOTP: ", otpKey);
                        //if no otp, generate one
                        if (otpKey === null) {
                            const otpGen = this.generateOTP();
                            await client.hSet(`register:otp:${ipAddress}`, { otp: otpGen });
                            otpKey = await client.hGet(`register:otp:${ipAddress}`, 'otp');
                            console.log("otpKey: ", otpKey);
                        }

                        //compare input to key in redis
                        if (otp !== otpKey || !otp) {
                            throw new Error("Invalid OTP");
                        } else {
                            await client.del(`register:otp:${ipAddress}`);
                            await client.del(key);
                        }
                    }
                    await this.adapter.insert(user);
                    return { message: "User registered successfully", user };
                }
            }
        },

        login: {
            rest: "POST /login",
            params: {
                username: { type: "string", pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$", required: true },
                password: { type: "string", required: true }
            },
            async handler(ctx) {
                const { username, password } = ctx.params;
                const user = await this.adapter.findOne({ username });
                const ipAddress = ctx.meta.clientIp;
                const client = await getRedisClient();
                var keyIP = `login_fail:attempts:${ipAddress}`;
                var key = `login_fail:password:${ipAddress}:${username}`;
                var ttl = await client.ttl(keyIP);

                const requestsMadeIP = await client.incr(keyIP);
                console.log("attempts: ", requestsMadeIP)
                if (requestsMadeIP >= 20) {
                    await client.expire(keyIP, 3600);
                    throw new Error("You have been locked for 1 hour due to more than 20 incorrect login attempts.");
                }

                //if first attempt, set the time for 1 min
                if (ttl < 0) {
                    await client.expire(keyIP, 60);
                    ttl = 60;
                }
                //check input in 1 min
                if (!user) {                    
                    throw new Error("No user found!");
                } else {
                    const isValid = await bcrypt.compare(password, user.password);
                    console.log("isValid: ", isValid);
                    if (isValid === false) {
                        const requestsMade = await client.incr(key);
                        console.log("wrong pass: ", requestsMade);

                        if (requestsMade === 3) {
                            await client.expire(key, 300);
                            throw new Error("Wrong password! Your account has been locked for 5 minutes due to more than 3 incorrect password attempts.");
                        }
                        else if (requestsMade > 3) {
                            await client.expire(key, 300, "NX");
                            throw new Error("Your account has been locked for 5 minutes due to more than 3 incorrect password attempts.");
                        }
                        throw new Error("Wrong password!" + (3 - requestsMade) + " attempts left.");
                    }
                    else {
                        await client.del(key);
                        await client.del(keyIP);
                        return { message: "User logined successfully", user };
                    }
                }

            }
        },

        forgotPassword: {
            rest: "POST /forgot-password",
            params: {
                username: { type: "string", pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$", required: true },
            },
            async handler(ctx) {
                const { username } = ctx.params;
                const ipAddress = ctx.meta.clientIp;
                const user = await this.adapter.findOne({ username });
                if (!user) {
                    throw new Error("User not found");
                }
                const client = await getRedisClient();
                //get otp from redis, if null, generate one
                let otpKey = await client.hGet(`forgot_password:otp:${ipAddress}:${username}`, 'otp');
                console.log("checkOTP: ", otpKey);
                if (otpKey === null) {
                    const otpGen = this.generateOTP();
                    const key = `forgot_password:otp:${ipAddress}:${username}`;
                    await client.hSet(key, { otp: otpGen });
                    //set otp expire in 5 min
                    await client.expire(key, 300);

                }
                else {
                    throw new Error("OTP is already sent to your registered contact. Please wait for 5 minutes to try again.");
                }

                return { message: "OTP sent to your registered contact." };
            }
        },


        resetPassword: {
            rest: "POST /reset-password",
            params: {
                username: { type: "string", pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$", required: true },
                newPassword: { type: "string", required: true },
                otp: { type: "string", required: true }
            },
            async handler(ctx) {
                const { username, newPassword, otp } = ctx.params;
                const user = await this.adapter.findOne({ username });
                const hash = await bcrypt.hash(newPassword, 10);
                const ipAddress = ctx.meta.clientIp;
                const key = `forgot_password:otp:${ipAddress}:${username}`;
                const keyIP = `reset_password:${ipAddress}`;
                const client = await getRedisClient();
                const requestMade = await client.incr(keyIP);
                //if more than 3 requests, lock the account in 5 min
                if (requestMade >= 3) {
                    await client.expire(keyIP, 300, "NX");
                    throw new Error("Your account has been locked for 5 minutes due to too many OTP requests.");
                }

                if (!user) {
                    throw new Error("User not found");
                }

                //get otp from redis and compare to input
                let otpKey = await client.hGet(key, 'otp');
                if (otp !== otpKey) {
                    throw new Error("Invalid OTP!" + (3 - requestMade) + " attempts left.");
                }
                else {
                    //update new password 
                    await this.adapter.updateById(user._id, { $set: { password: hash } });
                    await client.del(key);
                    await client.del(keyIP);
                }
                return { message: "Password reset successfully" };
            }
        }
    }
};

export default authService;
