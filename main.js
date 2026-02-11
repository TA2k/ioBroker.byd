'use strict';

const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const Json2iob = require('json2iob');
const bydapi = require('./lib/bydapi');

class Byd extends utils.Adapter {
    constructor(options) {
        super({
            ...options,
            name: 'byd',
        });

        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload', this.onUnload.bind(this));

        this.vehicleArray = [];
        this.json2iob = new Json2iob(this);
        this.updateInterval = null;
        this.refreshTimeout = null;
        this.session = null;
        this.deviceConfig = bydapi.DEFAULT_DEVICE_CONFIG;

        const jar = new CookieJar();
        this.requestClient = wrapper(
            axios.create({
                withCredentials: true,
                timeout: 3 * 60 * 1000,
                jar,
            }),
        );
    }

    async onReady() {
        this.setState('info.connection', false, true);

        if (this.config.interval < 60) {
            this.log.info('Set interval to minimum 60');
            this.config.interval = 60;
        }

        if (!this.config.username || !this.config.password) {
            this.log.error('Please set username and password in the instance settings');
            return;
        }

        this.subscribeStates('*');

        await this.login();

        if (!this.session) {
            return;
        }

        await this.getVehicleList();
        await this.updateVehicles();

        this.updateInterval = setInterval(() => {
            this.updateVehicles();
        }, this.config.interval * 1000);
    }

    async login() {
        const { outer } = bydapi.buildLoginRequest(
            this.config.username,
            this.config.password,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
        );

        const envelope = bydapi.encodeEnvelope(outer);

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/app/account/login`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: envelope },
        })
            .then(async res => {
                this.log.debug(`Login response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                this.log.debug(`Decoded login: ${JSON.stringify(decoded)}`);

                if (decoded.code !== '0') {
                    this.log.error(`Login failed: code=${decoded.code} message=${decoded.message || ''}`);
                    return;
                }

                const loginKey = bydapi.pwdLoginKey(this.config.password);
                const loginData = bydapi.decryptResponseData(decoded.respondData, loginKey);
                const token = loginData.token || {};
                const data = {
                    userId: token.userId,
                    signToken: token.signToken,
                    encryToken: token.encryToken,
                };
                this.session = {
                    userId: data.userId,
                    signToken: data.signToken,
                    encryToken: data.encryToken,
                };

                this.log.info('Login successful');
                this.setState('info.connection', true, true);
            })
            .catch(error => {
                this.log.error(`Login error: ${error.message}`);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async getVehicleList() {
        if (!this.session) {
            return;
        }

        const { outer, contentKey } = bydapi.buildVehicleListRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
        );

        const envelope = bydapi.encodeEnvelope(outer);

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/app/account/getAllListByUserId`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: envelope },
        })
            .then(async res => {
                this.log.debug(`Vehicle list response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);

                if (decoded.code !== '0') {
                    this.log.error(`Vehicle list failed: code=${decoded.code} message=${decoded.message || ''}`);
                    return;
                }

                const data = bydapi.decryptResponseData(decoded.respondData, contentKey);
                this.log.debug(`Vehicle list: ${JSON.stringify(data)}`);

                const vehicles = data.allCarList || [];

                for (const vehicle of vehicles) {
                    const vin = vehicle.vin;
                    if (!vin) {
                        continue;
                    }

                    const id = vin.toString().replace(this.FORBIDDEN_CHARS, '_');
                    this.vehicleArray.push(vehicle);

                    await this.extendObjectAsync(id, {
                        type: 'device',
                        common: { name: vehicle.carSeriesName || vehicle.vin },
                        native: {},
                    });

                    await this.setObjectNotExistsAsync(`${id}.remote`, {
                        type: 'channel',
                        common: { name: 'Remote Controls' },
                        native: {},
                    });

                    const remoteArray = [
                        { command: 'refresh', name: 'True = Refresh' },
                        { command: 'lock', name: 'True = Lock' },
                        { command: 'unlock', name: 'True = Unlock' },
                        { command: 'flash', name: 'True = Flash Lights' },
                        { command: 'horn', name: 'True = Horn' },
                        { command: 'climate', name: 'True = Start Climate, False = Stop Climate' },
                    ];

                    for (const remote of remoteArray) {
                        this.extendObject(`${id}.remote.${remote.command}`, {
                            type: 'state',
                            common: {
                                name: remote.name || '',
                                type: 'boolean',
                                role: 'button',
                                def: false,
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    }

                    this.json2iob.parse(id, vehicle, { forceIndex: true });
                }
            })
            .catch(error => {
                this.log.error(`Vehicle list error: ${error.message}`);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateVehicles() {
        for (const vehicle of this.vehicleArray) {
            const vin = vehicle.vin;
            const id = vin.toString().replace(this.FORBIDDEN_CHARS, '_');

            await this.pollVehicleRealtime(vin, id);
            await this.pollGpsInfo(vin, id);
            await this.getEnergyConsumption(vin, id);
        }
    }

    async pollVehicleRealtime(vin, id) {
        if (!this.session) {
            return;
        }

        // Trigger realtime data request
        const triggerReq = bydapi.buildVehicleRealtimeRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        let requestSerial = null;

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/vehicleInfo/vehicle/vehicleRealTimeRequest`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
        })
            .then(async res => {
                this.log.debug(`Realtime trigger response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                    requestSerial = data.requestSerial || null;
                }
            })
            .catch(error => {
                this.log.error(`Realtime trigger error: ${error.message}`);
            });

        // Poll for result (up to 10 attempts)
        for (let attempt = 0; attempt < 10; attempt++) {
            await this.sleep(1500);

            const pollReq = bydapi.buildVehicleRealtimeRequest(
                this.session,
                this.config.countryCode,
                this.config.language,
                this.deviceConfig,
                vin,
                requestSerial,
            );

            let ready = false;

            await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/vehicleInfo/vehicle/vehicleRealTimeResult`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(pollReq.outer) },
            })
                .then(async res => {
                    this.log.debug(`Realtime poll response: ${JSON.stringify(res.data)}`);
                    const decoded = bydapi.decodeEnvelope(res.data);
                    if (decoded.code === '0' && decoded.respondData) {
                        const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey);
                        this.log.debug(`Realtime data: ${JSON.stringify(data)}`);

                        if (bydapi.isRealtimeDataReady(data)) {
                            this.json2iob.parse(id, data, { forceIndex: true });
                            ready = true;
                        }
                    }
                })
                .catch(error => {
                    this.log.error(`Realtime poll error: ${error.message}`);
                });

            if (ready) {
                break;
            }
        }
    }

    async pollGpsInfo(vin, id) {
        if (!this.session) {
            return;
        }

        // Trigger GPS request
        const triggerReq = bydapi.buildGpsInfoRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        let requestSerial = null;

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/control/getGpsInfo`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
        })
            .then(async res => {
                this.log.debug(`GPS trigger response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                    requestSerial = data.requestSerial || null;
                }
            })
            .catch(error => {
                this.log.error(`GPS trigger error: ${error.message}`);
            });

        // Poll for result (up to 10 attempts)
        for (let attempt = 0; attempt < 10; attempt++) {
            await this.sleep(1500);

            const pollReq = bydapi.buildGpsInfoRequest(
                this.session,
                this.config.countryCode,
                this.config.language,
                this.deviceConfig,
                vin,
                requestSerial,
            );

            let ready = false;

            await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/getGpsInfoResult`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(pollReq.outer) },
            })
                .then(async res => {
                    this.log.debug(`GPS poll response: ${JSON.stringify(res.data)}`);
                    const decoded = bydapi.decodeEnvelope(res.data);
                    if (decoded.code === '0' && decoded.respondData) {
                        const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey);
                        this.log.debug(`GPS data: ${JSON.stringify(data)}`);

                        if (bydapi.isGpsDataReady(data)) {
                            this.json2iob.parse(`${id}.gps`, data, { forceIndex: true });
                            ready = true;
                        }
                    }
                })
                .catch(error => {
                    this.log.error(`GPS poll error: ${error.message}`);
                });

            if (ready) {
                break;
            }
        }
    }

    async getEnergyConsumption(vin, id) {
        if (!this.session) {
            return;
        }

        const req = bydapi.buildEnergyConsumptionRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/vehicleInfo/vehicle/getEnergyConsumption`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(req.outer) },
        })
            .then(async res => {
                this.log.debug(`Energy consumption response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, req.contentKey);
                    this.log.debug(`Energy consumption data: ${JSON.stringify(data)}`);
                    this.json2iob.parse(`${id}.energy`, data, { forceIndex: true });
                }
            })
            .catch(error => {
                this.log.error(`Energy consumption error: ${error.message}`);
            });
    }

    async sendRemoteControl(vin, instructionCode) {
        if (!this.session) {
            return;
        }

        // Trigger remote control
        const triggerReq = bydapi.buildRemoteControlRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
            instructionCode,
        );

        let requestSerial = null;

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/control/remoteControl`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
        })
            .then(async res => {
                this.log.debug(`Remote control trigger response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code !== '0') {
                    this.log.error(`Remote control failed: code=${decoded.code} message=${decoded.message || ''}`);
                } else if (decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                    requestSerial = data.requestSerial || null;
                    this.log.debug(`Remote control triggered, requestSerial: ${requestSerial}`);
                }
            })
            .catch(error => {
                this.log.error(`Remote control error: ${error.message}`);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });

        if (!requestSerial) {
            return;
        }

        // Poll for result (up to 10 attempts)
        for (let attempt = 0; attempt < 10; attempt++) {
            await this.sleep(1500);

            const pollReq = bydapi.buildRemoteControlRequest(
                this.session,
                this.config.countryCode,
                this.config.language,
                this.deviceConfig,
                vin,
                instructionCode,
                requestSerial,
            );

            let ready = false;

            await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/remoteControlResult`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(pollReq.outer) },
            })
                .then(async res => {
                    this.log.debug(`Remote control poll response: ${JSON.stringify(res.data)}`);
                    const decoded = bydapi.decodeEnvelope(res.data);
                    if (decoded.code === '0' && decoded.respondData) {
                        const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey);
                        this.log.debug(`Remote control result: ${JSON.stringify(data)}`);

                        if (bydapi.isRemoteControlReady(data)) {
                            const success = data.controlState === '1' || data.controlState === 1;
                            if (success) {
                                this.log.info(`Remote control success: ${instructionCode}`);
                            } else {
                                this.log.warn(`Remote control completed with state: ${data.controlState}`);
                            }
                            ready = true;
                        }
                    }
                })
                .catch(error => {
                    this.log.error(`Remote control poll error: ${error.message}`);
                });

            if (ready) {
                break;
            }
        }
    }

    async onStateChange(id, state) {
        if (!state) {
            return;
        }

        const deviceId = id.split('.')[2];
        const folder = id.split('.')[3];
        const command = id.split('.')[4];

        // Handle ack===true to update remote states
        if (state.ack && folder === 'remote') {
            return;
        }

        // Handle ack===false for commands
        if (!state.ack && folder === 'remote') {
            if (command === 'refresh') {
                this.updateVehicles();
                await this.setStateAsync(id, false, true);
                return;
            }

            const commandMap = {
                lock: '10',
                unlock: '11',
                flash: '20',
                horn: '21',
                climate: state.val ? '30' : '31',
            };

            const instructionCode = commandMap[command];
            if (!instructionCode) {
                this.log.warn(`Unknown command: ${command}`);
                return;
            }

            this.log.info(`Sending remote command: ${command} for ${deviceId}`);

            await this.sendRemoteControl(deviceId, instructionCode);

            // Acknowledge the state change
            await this.setStateAsync(id, state.val, true);

            // Schedule refresh after command
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            this.refreshTimeout = setTimeout(() => {
                this.updateVehicles();
            }, 10 * 1000);
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    onUnload(callback) {
        try {
            this.setState('info.connection', false, true);
            this.updateInterval && clearInterval(this.updateInterval);
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            callback();
        } catch {
            callback();
        }
    }
}

if (require.main !== module) {
    module.exports = options => new Byd(options);
} else {
    new Byd();
}
