'use strict';

const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const mqtt = require('mqtt');
const Json2iob = require('json2iob');
const bydapi = require('./lib/bydapi');
const devicegen = require('./lib/devicegen');
const descriptions = require('./lib/descriptions.json');
const states = require('./lib/states.json');

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
        this.telemetryInterval = null;
        this.gpsInterval = null;
        this.refreshTimeout = null;
        this.session = null;
        this.deviceConfig = bydapi.DEFAULT_DEVICE_CONFIG;
        // Track unsupported endpoints per VIN to avoid repeated 1001 errors
        this.unsupportedEndpoints = {}; // { vin: Set(['energy', 'hvac', 'charging']) }
        // Cache realtime data for fallback
        this.realtimeCache = {}; // { vin: {...} }
        // Track vehicle on/off state for smart GPS polling
        this.vehicleOnState = {}; // { vin: boolean }
        // MQTT client for push notifications
        this.mqttClient = null;
        this.mqttBroker = null;
        // Pending MQTT waiters for trigger+wait pattern
        // Map: requestSerial -> { resolve, reject, vin, type, timestamp }
        this.pendingMqttWaiters = new Map();
        // Pending remote control commands waiting for MQTT result
        // Map: requestSerial -> { resolve, reject, vin, command, timestamp }
        this.pendingRemoteControls = new Map();
        // MQTT wait timeout in ms (pyBYD uses 8 seconds for commands)
        this.mqttWaitTimeout = 8000;

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

        if (!this.config.username || !this.config.password) {
            this.log.error('Please set username and password in the instance settings');
            return;
        }

        // Load or generate device fingerprint (persistent across restarts)
        await this.loadOrGenerateDeviceConfig();

        this.subscribeStates('*');

        await this.login();

        if (!this.session) {
            return;
        }

        await this.getVehicleList();

        // Clean up old subfolder structure from previous versions
        await this.cleanupOldStateStructure();

        // Verify control PIN at startup if configured
        if (this.config.controlPin && this.vehicleArray.length > 0) {
            const firstVin = this.vehicleArray[0].vin;
            this.log.info('Verifying control PIN at startup...');
            const result = await this.verifyControlPassword(firstVin);
            if (!result.success) {
                if (result.noPinInApp) {
                    // Don't repeat error - already logged in verifyControlPassword
                    this.log.warn('Remote control disabled - no PIN set in BYD app');
                } else {
                    this.log.error(`Control PIN verification failed: ${result.error}`);
                    this.log.error('Remote control commands will not work until PIN is corrected');
                }
            }
        } else if (!this.config.controlPin) {
            this.log.warn('No control PIN configured in ioBroker adapter settings');
            this.log.warn('Remote control commands require a PIN (same as in BYD app)');
        }

        // Connect MQTT for real-time updates
        await this.connectMqtt();

        // Initial data fetch
        await this.updateVehicles();

        // Start polling intervals (like Home Assistant integration)
        this.startPolling();
    }

    /**
     * Start telemetry and GPS polling intervals.
     * Pattern: HTTP trigger -> wait for MQTT -> HTTP poll fallback
     */
    startPolling() {
        const pollInterval = Math.max(30, Math.min(900, this.config.pollInterval || 300));
        const gpsPollInterval = Math.max(30, Math.min(900, this.config.gpsPollInterval || 300));

        this.log.info(`Telemetry poll interval: ${pollInterval}s, GPS poll interval: ${gpsPollInterval}s`);
        if (this.config.smartGpsPolling) {
            this.log.info(
                `Smart GPS polling enabled: active=${this.config.gpsActiveInterval || 30}s, inactive=${this.config.gpsInactiveInterval || 600}s`,
            );
        }

        // Telemetry polling
        this.telemetryInterval = setInterval(() => {
            this.pollAllVehiclesRealtime();
        }, pollInterval * 1000);

        // GPS polling (with smart polling support)
        this.scheduleGpsPolling();
    }

    /**
     * Schedule GPS polling with optional smart interval based on vehicle state
     */
    scheduleGpsPolling() {
        if (this.gpsInterval) {
            clearInterval(this.gpsInterval);
        }

        let intervalSeconds;
        if (this.config.smartGpsPolling) {
            // Check if any vehicle is on
            const anyVehicleOn = Object.values(this.vehicleOnState).some(v => v === true);
            intervalSeconds = anyVehicleOn
                ? Math.max(10, Math.min(300, this.config.gpsActiveInterval || 30))
                : Math.max(60, Math.min(3600, this.config.gpsInactiveInterval || 600));
            this.log.debug(`Smart GPS polling: vehicleOn=${anyVehicleOn}, interval=${intervalSeconds}s`);
        } else {
            intervalSeconds = Math.max(30, Math.min(900, this.config.gpsPollInterval || 300));
        }

        this.gpsInterval = setInterval(() => {
            this.pollAllVehiclesGps();
            // Re-evaluate interval if smart polling enabled
            if (this.config.smartGpsPolling) {
                this.scheduleGpsPolling();
            }
        }, intervalSeconds * 1000);
    }

    /**
     * Poll realtime data for all vehicles using trigger + MQTT wait + HTTP fallback
     */
    async pollAllVehiclesRealtime() {
        this.log.debug(`Scheduled poll: realtime for ${this.vehicleArray.length} vehicle(s)`);
        for (const vehicle of this.vehicleArray) {
            await this.pollVehicleRealtimeWithMqtt(vehicle.vin);
        }
    }

    /**
     * Poll GPS data for all vehicles
     */
    async pollAllVehiclesGps() {
        this.log.debug(`Scheduled poll: GPS for ${this.vehicleArray.length} vehicle(s)`);
        for (const vehicle of this.vehicleArray) {
            await this.pollGpsWithMqtt(vehicle.vin);
        }
    }

    /**
     * Poll vehicle realtime with MQTT-first pattern (like pyBYD/HA)
     * 1. HTTP trigger -> get requestSerial
     * 2. Wait for MQTT vehicleInfo event (8s timeout)
     * 3. Fall back to HTTP polling if MQTT doesn't deliver
     *
     * @param {string} vin - Vehicle identification number
     */
    async pollVehicleRealtimeWithMqtt(vin) {
        if (!this.session) {
            return;
        }

        // Step 1: Trigger request
        const triggerReq = bydapi.buildVehicleRealtimeRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        let requestSerial = null;

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/vehicleInfo/vehicle/vehicleRealTimeRequest`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
            });

            const decoded = bydapi.decodeEnvelope(res.data);
            if (decoded.code === '0' && decoded.respondData) {
                const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                requestSerial = data.requestSerial || null;

                // If trigger response already has data, use it
                if (bydapi.isRealtimeDataReady(data)) {
                    this.log.debug(`Realtime data ready from trigger for ${vin}`);
                    this.processRealtimeData(vin, data);
                    return;
                }
            } else if (bydapi.isSessionExpired(decoded.code)) {
                this.log.warn(`Session expired during realtime trigger for ${vin} (code=${decoded.code})`);
                await this.handleSessionExpired(decoded.code, 'realtimeTrigger');
                return;
            } else if (decoded.code !== '0') {
                this.log.warn(
                    `Realtime trigger failed for ${vin}: code=${decoded.code}, message=${decoded.message || 'unknown'}`,
                );
                return;
            }
        } catch (error) {
            this.log.error(`Realtime trigger error for ${vin}: ${error.message}`);
            return;
        }

        if (!requestSerial) {
            this.log.warn(`No requestSerial from realtime trigger for ${vin}`);
            return;
        }

        // Step 2: Wait for MQTT vehicleInfo event
        if (this.mqttClient?.connected) {
            this.log.debug(`Waiting for MQTT vehicleInfo for ${vin} (serial: ${requestSerial})`);
            const mqttData = await this.waitForMqttVehicleInfo(vin, requestSerial);
            if (mqttData) {
                this.log.debug(`Realtime data received via MQTT for ${vin}`);
                this.processRealtimeData(vin, mqttData);
                return;
            }
            this.log.debug(`MQTT timeout for ${vin}, falling back to HTTP polling`);
        }

        // Step 3: HTTP poll fallback
        await this.pollRealtimeHttpFallback(vin, requestSerial, triggerReq.contentKey);
    }

    /**
     * Wait for MQTT vehicleInfo event with timeout
     *
     * @param {string} vin - Vehicle identification number
     * @param {string} requestSerial - Request serial from trigger response
     */
    waitForMqttVehicleInfo(vin, requestSerial) {
        return new Promise(resolve => {
            const timeout = setTimeout(() => {
                this.pendingMqttWaiters.delete(requestSerial);
                resolve(null);
            }, this.mqttWaitTimeout);

            this.pendingMqttWaiters.set(requestSerial, {
                resolve: data => {
                    clearTimeout(timeout);
                    this.pendingMqttWaiters.delete(requestSerial);
                    resolve(data);
                },
                vin,
                type: 'vehicleInfo',
                timestamp: Date.now(),
            });
        });
    }

    /**
     * HTTP polling fallback for realtime data
     *
     * @param {string} vin - Vehicle identification number
     * @param {string} requestSerial - Request serial from trigger response
     * @param {string} contentKey - AES content key for decryption
     */
    async pollRealtimeHttpFallback(vin, requestSerial, contentKey) {
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

            try {
                const res = await this.requestClient({
                    method: 'post',
                    url: `${bydapi.BASE_URL}/vehicleInfo/vehicle/vehicleRealTimeResult`,
                    headers: {
                        'User-Agent': bydapi.USER_AGENT,
                        'Content-Type': 'application/json; charset=UTF-8',
                    },
                    data: { request: bydapi.encodeEnvelope(pollReq.outer) },
                });

                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey || contentKey);
                    if (bydapi.isRealtimeDataReady(data)) {
                        this.log.debug(`Realtime data ready via HTTP poll for ${vin} (attempt ${attempt + 1})`);
                        this.processRealtimeData(vin, data);
                        return;
                    }
                }
            } catch (error) {
                this.log.error(`Realtime poll error for ${vin}: ${error.message}`);
            }
        }
        this.log.warn(`Realtime data not ready after 10 poll attempts for ${vin}`);
    }

    /**
     * Process realtime data - update cache and states
     *
     * @param {string} vin - Vehicle identification number
     * @param {object} data - Realtime data from API response
     */
    processRealtimeData(vin, data) {
        this.realtimeCache[vin] = data;

        // Update vehicle on/off state for smart GPS polling
        const wasOn = this.vehicleOnState[vin];
        const isOn = this.isVehicleOn(data);
        this.vehicleOnState[vin] = isOn;

        // Re-schedule GPS if vehicle state changed and smart polling enabled
        if (this.config.smartGpsPolling && wasOn !== isOn) {
            this.log.debug(`Vehicle ${vin} state changed: ${wasOn} -> ${isOn}, rescheduling GPS`);
            this.scheduleGpsPolling();
        }

        // Parse into ioBroker states
        this.log.debug(
            `Writing realtime data to ${vin}.status (soc=${data.elecPercent}, mileage=${data.totalMileage})`,
        );
        this.json2iob.parse(`${vin}.status`, data, {
            forceIndex: true,
            descriptions,
            states,
        });

        // Update remote state buttons based on realtime data
        if (data.leftFrontDoorLock !== undefined) {
            const isLocked = data.leftFrontDoorLock === 2;
            this.log.debug(`Status leftFrontDoorLock=${data.leftFrontDoorLock} -> remote.lock=${isLocked}`);
            this.setStateAsync(`${vin}.remote.lock`, isLocked, true);
        }
        if (data.batteryHeatState !== undefined) {
            const isOn = data.batteryHeatState > 0;
            this.log.debug(`Status batteryHeatState=${data.batteryHeatState} -> remote.batteryHeat=${isOn}`);
            this.setStateAsync(`${vin}.remote.batteryHeat`, isOn, true);
        }
        if (data.mainSeatHeatState !== undefined) {
            const isOn = data.mainSeatHeatState > 0;
            this.log.debug(`Status mainSeatHeatState=${data.mainSeatHeatState} -> remote.seatHeat=${isOn}`);
            this.setStateAsync(`${vin}.remote.seatHeat`, isOn, true);
        }
    }

    /**
     * Check if vehicle is on based on realtime data
     *
     * @param {object} data - Realtime data from API response
     */
    isVehicleOn(data) {
        // Vehicle is considered "on" if engine is running, speed > 0, or charging
        if (data.engineStatus === 1) {
            return true;
        }
        if (data.speed > 0) {
            return true;
        }
        if (data.vehicleState === 1) {
            return true;
        }
        // chargeState: 1 = charging (confirmed)
        if (data.chargeState === 1) {
            return true;
        }
        return false;
    }

    /**
     * Poll GPS with MQTT-first pattern
     *
     * @param {string} vin - Vehicle identification number
     */
    async pollGpsWithMqtt(vin) {
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

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/getGpsInfo`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
            });

            const decoded = bydapi.decodeEnvelope(res.data);
            if (decoded.code === '0' && decoded.respondData) {
                const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                requestSerial = data.requestSerial || null;

                // Check if GPS data is already ready in trigger response
                if (bydapi.isGpsDataReady(data)) {
                    this.log.debug(`GPS data ready from trigger for ${vin}`);
                    this.processGpsData(vin, data);
                    return;
                }
            } else if (bydapi.isSessionExpired(decoded.code)) {
                this.log.warn(`Session expired during GPS trigger for ${vin} (code=${decoded.code})`);
                await this.handleSessionExpired(decoded.code, 'gpsTrigger');
                return;
            } else if (decoded.code !== '0') {
                this.log.warn(
                    `GPS trigger failed for ${vin}: code=${decoded.code}, message=${decoded.message || 'unknown'}`,
                );
                return;
            }
        } catch (error) {
            this.log.error(`GPS trigger error for ${vin}: ${error.message}`);
            return;
        }

        if (!requestSerial) {
            this.log.warn(`No requestSerial from GPS trigger for ${vin}`);
            return;
        }

        // Wait for MQTT or fall back to HTTP
        if (this.mqttClient?.connected) {
            this.log.debug(`Waiting for MQTT GPS for ${vin} (serial: ${requestSerial})`);
            const mqttData = await this.waitForMqttGps(vin, requestSerial);
            if (mqttData) {
                this.log.debug(`GPS data received via MQTT for ${vin}`);
                this.processGpsData(vin, mqttData);
                return;
            }
            this.log.debug(`MQTT timeout for GPS ${vin}, falling back to HTTP polling`);
        }

        // HTTP poll fallback
        await this.pollGpsHttpFallback(vin, requestSerial, triggerReq.contentKey);
    }

    /**
     * Wait for MQTT GPS event with timeout
     *
     * @param {string} vin - Vehicle identification number
     * @param {string} requestSerial - Request serial from trigger response
     */
    waitForMqttGps(vin, requestSerial) {
        return new Promise(resolve => {
            const timeout = setTimeout(() => {
                this.pendingMqttWaiters.delete(requestSerial);
                resolve(null);
            }, this.mqttWaitTimeout);

            this.pendingMqttWaiters.set(requestSerial, {
                resolve: data => {
                    clearTimeout(timeout);
                    this.pendingMqttWaiters.delete(requestSerial);
                    resolve(data);
                },
                vin,
                type: 'gps',
                timestamp: Date.now(),
            });
        });
    }

    /**
     * HTTP polling fallback for GPS data
     *
     * @param {string} vin - Vehicle identification number
     * @param {string} requestSerial - Request serial from trigger response
     * @param {string} contentKey - AES content key for decryption
     */
    async pollGpsHttpFallback(vin, requestSerial, contentKey) {
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

            try {
                const res = await this.requestClient({
                    method: 'post',
                    url: `${bydapi.BASE_URL}/control/getGpsInfoResult`,
                    headers: {
                        'User-Agent': bydapi.USER_AGENT,
                        'Content-Type': 'application/json; charset=UTF-8',
                    },
                    data: { request: bydapi.encodeEnvelope(pollReq.outer) },
                });

                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey || contentKey);
                    if (bydapi.isGpsDataReady(data)) {
                        this.log.debug(`GPS data ready via HTTP poll for ${vin} (attempt ${attempt + 1})`);
                        this.processGpsData(vin, data);
                        return;
                    }
                }
            } catch (error) {
                this.log.error(`GPS poll error for ${vin}: ${error.message}`);
            }
        }
        this.log.warn(`GPS data not ready after 10 poll attempts for ${vin}`);
    }

    /**
     * Process GPS data - update states (flat structure under status.*)
     *
     * @param {string} vin - Vehicle identification number
     * @param {object} data - GPS data from API response
     */
    processGpsData(vin, data) {
        // GPS response can have nested data structure
        const gpsData = data.data || data;
        this.log.debug(`Writing GPS data to ${vin}.status (lat=${gpsData.latitude}, lon=${gpsData.longitude})`);
        // Flatten GPS data directly into status (no subfolder)
        this.json2iob.parse(`${vin}.status`, gpsData, {
            forceIndex: true,
            descriptions,
            states,
        });
    }

    /**
     * Clean up old subfolder structure from previous versions.
     * Deletes: status.charging, status.gps, status.hvac, status.energy, status.mqtt
     * All data now goes directly into status.*
     */
    async cleanupOldStateStructure() {
        const oldSubfolders = ['charging', 'gps', 'hvac', 'energy', 'mqtt'];

        for (const vehicle of this.vehicleArray) {
            const vin = vehicle.vin;
            for (const subfolder of oldSubfolders) {
                const objectId = `${vin}.status.${subfolder}`;
                try {
                    await this.delObjectAsync(objectId, { recursive: true });
                    this.log.info(`Deleted old subfolder: ${objectId}`);
                } catch {
                    // Object doesn't exist, ignore
                }
            }
        }
    }

    async loadOrGenerateDeviceConfig() {
        // Try to load existing device fingerprint from adapter state
        const fpState = await this.getStateAsync('info.deviceFingerprint');
        let fingerprint = null;

        if (fpState && fpState.val && typeof fpState.val === 'string') {
            try {
                fingerprint = JSON.parse(fpState.val);
                this.log.debug('Loaded existing device fingerprint');
            } catch {
                this.log.warn('Failed to parse stored fingerprint, generating new one');
            }
        }

        if (!fingerprint) {
            // Generate new device fingerprint (without app version fields)
            fingerprint = devicegen.generateDeviceProfile();
            this.log.info(`Generated device: ${fingerprint.model} (${fingerprint.mobileBrand})`);

            // Store fingerprint (only static device data, no app version)
            await this.setObjectNotExistsAsync('info.deviceFingerprint', {
                type: 'state',
                common: {
                    name: 'Device Fingerprint',
                    type: 'string',
                    role: 'json',
                    read: true,
                    write: false,
                },
                native: {},
            });
            await this.setStateAsync('info.deviceFingerprint', JSON.stringify(fingerprint), true);
        }

        // Add dynamic app fields (version, timezone etc.) - not persisted
        this.deviceConfig = devicegen.addAppFields(fingerprint);
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
                // this.log.debug(`Login response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                this.log.debug(`Decoded login: ${JSON.stringify(decoded)}`);

                if (decoded.code !== '0') {
                    this.log.error(`Login failed: code=${decoded.code} message=${decoded.message || ''}`);
                    return;
                }

                const loginKey = bydapi.pwdLoginKey(this.config.password);
                const loginData = bydapi.decryptResponseData(decoded.respondData, loginKey);
                const token = loginData.token || {};

                this.session = {
                    userId: token.userId,
                    signToken: token.signToken,
                    encryToken: token.encryToken,
                };

                this.log.info('Login successful');
                this.log.debug(`DEBUG login: session set, userId=${this.session.userId}`);
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
                // this.log.debug(`Vehicle list response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);

                if (decoded.code !== '0') {
                    if (await this.handleSessionExpired(decoded.code, 'getVehicleList')) {
                        this.log.info('Session restored, vehicle list will refresh on next cycle');
                    } else if (!bydapi.isSessionExpired(decoded.code)) {
                        this.log.error(`Vehicle list failed: code=${decoded.code}`);
                    }
                    return;
                }

                const data = bydapi.decryptResponseData(decoded.respondData, contentKey);
                this.log.debug(`Vehicle list: ${JSON.stringify(data)}`);

                // Sample: [{
                //   "vin": "LGXXXXXXXXXXX00000", "autoAlias": "BYD SEALION 7", "autoPlate": "AB123CD",
                //   "brandName": "BYD", "modelName": "BYD SEALION 7", "modelId": 28,
                //   "totalMileage": 13060, "energyType": "0", "carType": 0,
                //   "defaultCar": 1, "permissionStatus": 3, "tboxVersion": "3",
                //   "vehicleState": "0", "vehicleTimeZone": "Europe/Vienna",
                //   "autoBoughtTime": 1742770800000, "yunActiveTime": 1742770800000,
                //   "cfPic": { "picMainUrl": "https://...", "picSetUrl": "https://..." },
                //   "vehicleFunLearnInfo": {
                //     "bookingCharge": 2, "batteryHeating": 1, "steeringWheelHeating": 1,
                //     "openWindowLearnInfo": 1, "trunkLearnInfo": 1, "gpsLearnInfo": 1, ...
                //   },
                //   "rangeDetailList": [{ "code": "2", "name": "Schlüssel und Steuerung", ... }]
                // }]
                const vehicles = data || [];
                this.log.info(`Found ${vehicles.length} vehicle(s)`);

                for (const vehicle of vehicles) {
                    const vin = vehicle.vin;
                    if (!vin) {
                        continue;
                    }

                    this.vehicleArray.push(vehicle);

                    // Device name: Model + Plate (e.g. "BYD SEALION 7 - KO591ET")
                    const modelName = vehicle.modelName || vehicle.autoAlias || 'BYD';
                    const plate = vehicle.autoPlate || '';
                    const deviceName = plate ? `${modelName} - ${plate}` : modelName;

                    await this.extendObject(vin, {
                        type: 'device',
                        common: { name: deviceName },
                        native: {},
                    });

                    // Channel: general - static vehicle information
                    await this.setObjectNotExistsAsync(`${vin}.general`, {
                        type: 'channel',
                        common: { name: 'General Information' },
                        native: {},
                    });

                    // Parse static vehicle data into general channel
                    const generalData = {
                        vin: vehicle.vin,
                        modelName: vehicle.modelName,
                        brandName: vehicle.brandName,
                        autoAlias: vehicle.autoAlias,
                        autoPlate: vehicle.autoPlate,
                        energyType: vehicle.energyType,
                        tboxVersion: vehicle.tboxVersion,
                        vehicleTimeZone: vehicle.vehicleTimeZone,
                        autoBoughtTime: vehicle.autoBoughtTime,
                        yunActiveTime: vehicle.yunActiveTime,
                    };
                    this.json2iob.parse(`${vin}.general`, generalData, {
                        forceIndex: true,
                        descriptions,
                        states,
                    });

                    // Channel: status - realtime data from API/MQTT
                    await this.setObjectNotExistsAsync(`${vin}.status`, {
                        type: 'channel',
                        common: { name: 'Vehicle Status' },
                        native: {},
                    });

                    // Channel: remote - control commands
                    await this.setObjectNotExistsAsync(`${vin}.remote`, {
                        type: 'channel',
                        common: { name: 'Remote Controls' },
                        native: {},
                    });

                    const remoteArray = [
                        { command: 'refresh', name: 'Refresh Data' },
                        { command: 'lock', name: 'Door Lock true = locked, false = unlocked' },
                        { command: 'flash', name: 'Flash Lights' },
                        { command: 'findCar', name: 'Find Car (Flash + Horn)' },
                        { command: 'closeWindows', name: 'Close Windows' },
                        { command: 'climate', name: 'Climate Control true = on, false = off' },
                        { command: 'seatHeat', name: 'Seat Heating true = on, false = off' },
                        { command: 'batteryHeat', name: 'Battery Heating true = on, false = off' },
                    ];

                    for (const remote of remoteArray) {
                        this.extendObject(`${vin}.remote.${remote.command}`, {
                            type: 'state',
                            common: {
                                name: remote.name || '',
                                desc: remote.desc || '',
                                type: 'boolean',
                                role: 'button',
                                def: false,
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    }
                }
            })
            .catch(error => {
                this.log.error(`Vehicle list error: ${error.message}`);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateVehicles() {
        // Check session before starting updates
        if (!this.session) {
            this.log.warn('No session - attempting re-login before vehicle update');
            await this.login();
            if (!this.session) {
                this.log.error('Re-login failed, skipping vehicle update');
                return;
            }
        }

        for (const vehicle of this.vehicleArray) {
            await this.updateSingleVehicle(vehicle.vin);
        }
    }

    /**
     * Update data for a single vehicle via HTTP
     *
     * @param {string} vin - Vehicle VIN (also used as object ID)
     */
    async updateSingleVehicle(vin) {
        this.log.debug(`DEBUG updateSingleVehicle: vin=${vin}, session=${this.session ? 'exists' : 'null'}`);
        if (!this.session) {
            this.log.warn('No session for vehicle update');
            return;
        }

        await this.pollVehicleRealtime(vin);
        await this.pollGpsInfo(vin);
        await this.getVehicleStatusEndpoints(vin);
    }

    /**
     * Handle session expired error - re-login and return true if successful
     *
     * @param {string} code - API error code
     * @param {string} context - Context description for logging
     * @returns {Promise<boolean>} - True if re-login succeeded
     */
    async handleSessionExpired(code, context) {
        if (!bydapi.isSessionExpired(code)) {
            return false;
        }
        this.log.warn(`Session expired (code=${code}) in ${context} - re-authenticating`);
        this.log.debug(`DEBUG: Setting session=null in handleSessionExpired (code=${code}, context=${context})`);
        this.session = null;
        this.setState('info.connection', false, true);
        await this.login();
        if (this.session) {
            // Reconnect MQTT with new session tokens
            this.reconnectMqtt();
        }
        return !!this.session;
    }

    /**
     * Reconnect MQTT with current session tokens.
     * Called after re-login to update credentials.
     */
    reconnectMqtt() {
        if (this.mqttClient) {
            this.log.info('Reconnecting MQTT with new session tokens');
            this.mqttClient.end(true);
            this.mqttClient = null;
        }
        if (this.session && this.vehicleArray?.length > 0) {
            this.connectMqtt();
        }
    }

    /**
     * Generic poll endpoint that triggers a request and polls for results
     *
     * @param {string} vin - Vehicle VIN
     * @param {object} endpoint - Endpoint config
     */
    async pollEndpoint(vin, endpoint) {
        if (!this.session) {
            return;
        }

        // Trigger request
        const triggerReq = endpoint.builder(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        let requestSerial = null;

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}${endpoint.triggerUrl}`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
        })
            .then(async res => {
                // this.log.debug(`${endpoint.name} trigger response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                    requestSerial = data.requestSerial || null;
                }
            })
            .catch(error => {
                this.log.error(`${endpoint.name} trigger error: ${error.message}`);
            });

        // Poll for result (up to 10 attempts)
        for (let attempt = 0; attempt < 10; attempt++) {
            await this.sleep(1500);

            const pollReq = endpoint.builder(
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
                url: `${bydapi.BASE_URL}${endpoint.pollUrl}`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(pollReq.outer) },
            })
                .then(async res => {
                    // this.log.debug(`${endpoint.name} poll response: ${JSON.stringify(res.data)}`);
                    const decoded = bydapi.decodeEnvelope(res.data);
                    if (decoded.code === '0' && decoded.respondData) {
                        const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey);
                        this.log.debug(`${endpoint.name} data: ${JSON.stringify(data)}`);

                        if (endpoint.isReady(data)) {
                            if (endpoint.cache) {
                                this.realtimeCache[vin] = data;
                            }
                            const parseOpts = { forceIndex: true, descriptions, states };
                            if (endpoint.channelName) {
                                parseOpts.channelName = endpoint.channelName;
                            }
                            this.json2iob.parse(
                                `${vin}.status${endpoint.channel ? `.${endpoint.channel}` : ''}`,
                                data,
                                parseOpts,
                            );
                            ready = true;
                        }
                    }
                })
                .catch(error => {
                    this.log.error(`${endpoint.name} poll error: ${error.message}`);
                });

            if (ready) {
                break;
            }
        }
    }

    async pollVehicleRealtime(vin) {
        await this.pollEndpoint(vin, {
            name: 'Realtime',
            triggerUrl: '/vehicleInfo/vehicle/vehicleRealTimeRequest',
            pollUrl: '/vehicleInfo/vehicle/vehicleRealTimeResult',
            builder: bydapi.buildVehicleRealtimeRequest,
            isReady: bydapi.isRealtimeDataReady,
            cache: true,
        });
    }

    async pollGpsInfo(vin) {
        // If MQTT is connected, only trigger - MQTT will deliver the result
        if (this.mqttClient?.connected) {
            this.log.debug('GPS: MQTT connected, trigger only (no API poll)');
            await this.triggerGps(vin);
            return;
        }

        // Fallback: MQTT not connected, use API polling
        this.log.debug('GPS: MQTT not connected, using API poll fallback');
        await this.pollEndpoint(vin, {
            name: 'GPS',
            triggerUrl: '/control/getGpsInfo',
            pollUrl: '/control/getGpsInfoResult',
            builder: bydapi.buildGpsInfoRequest,
            isReady: bydapi.isGpsDataReady,
            // No channel - flat structure directly in status
        });
    }

    /**
     * Trigger GPS request (result comes via MQTT)
     *
     * @param vin - Vehicle VIN
     */
    async triggerGps(vin) {
        const triggerReq = bydapi.buildGpsInfoRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/control/getGpsInfo`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
        })
            .then(res => {
                this.log.debug(`GPS trigger response: ${JSON.stringify(res.data)}`);
            })
            .catch(error => {
                this.log.warn(`GPS trigger failed: ${error.message}`);
            });
    }

    /**
     * Fetch HVAC status and parse into ioBroker states (flat structure)
     * Unwraps statusNow to match Realtime structure
     *
     * @param {string} vin - Vehicle VIN
     */
    async fetchHvacStatus(vin) {
        if (!this.session) {
            return;
        }

        // Skip if endpoint is known to be unsupported for this VIN
        if (this.unsupportedEndpoints[vin]?.has('hvac')) {
            return;
        }

        const req = bydapi.buildHvacStatusRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/control/getStatusNow`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(req.outer) },
        })
            .then(async res => {
                const decoded = bydapi.decodeEnvelope(res.data);
                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, req.contentKey);
                    // Unwrap statusNow to match Realtime flat structure
                    const hvacData = data.statusNow || data;
                    this.log.debug(`HVAC data: ${JSON.stringify(hvacData)}`);
                    // Flat structure - directly into status
                    this.json2iob.parse(`${vin}.status`, hvacData, {
                        forceIndex: true,
                        descriptions,
                        states,
                    });
                } else if (bydapi.isSessionExpired(decoded.code)) {
                    await this.handleSessionExpired(decoded.code, 'hvac');
                } else if (bydapi.isEndpointNotSupported(decoded.code)) {
                    this.log.info(`HVAC endpoint not supported for ${vin}`);
                    if (!this.unsupportedEndpoints[vin]) {
                        this.unsupportedEndpoints[vin] = new Set();
                    }
                    this.unsupportedEndpoints[vin].add('hvac');
                }
            })
            .catch(error => {
                this.log.error(`HVAC error: ${error.message}`);
            });
    }

    /**
     * Fetch HVAC status if vehicle is on (like Home Assistant).
     * Energy and Charging endpoints removed - data already in Realtime.
     *
     * @param {string} vin - Vehicle VIN
     */
    async getVehicleStatusEndpoints(vin) {
        // Only fetch HVAC when vehicle is on (like HA)
        // HVAC provides additional fields not in Realtime:
        // acSwitch, windMode, airConditioningMode, tempOutCar, defrost status, etc.
        const isOn = this.vehicleOnState[vin];
        if (!isOn) {
            this.log.debug(`Skipping HVAC fetch for ${vin} - vehicle is off`);
            return;
        }

        await this.fetchHvacStatus(vin);

        // TEMPORARY: Compare Charging soc vs Realtime elecPercent
        await this.compareChargingSocWithRealtime(vin);
    }

    /**
     * TEMPORARY: Fetch Charging endpoint and compare soc with elecPercent from Realtime
     * Remove after testing!
     *
     * @param {string} vin - Vehicle VIN
     */
    async compareChargingSocWithRealtime(vin) {
        if (!this.session) {
            return;
        }

        const req = bydapi.buildChargingStatusRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
        );

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/smartCharge/homePage`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(req.outer) },
            });

            const decoded = bydapi.decodeEnvelope(res.data);
            if (decoded.code === '0' && decoded.respondData) {
                const data = bydapi.decryptResponseData(decoded.respondData, req.contentKey);
                const chargingSoc = data.soc;
                const realtime = this.realtimeCache[vin] || {};

                // State code mappings for logging
                const chargingStateMap = {
                    '-1': 'Disconnected',
                    0: 'Not Charging',
                    1: 'Charging',
                    15: 'Gun Connected',
                };
                const connectStateMap = { '-1': 'Unknown', 0: 'Disconnected', 1: 'Connected' };
                const chargeStateMap = { '-1': 'Unknown', 0: 'Not Charging', 1: 'Charging', 2: 'Charged' };

                const chargingLabel = chargingStateMap[data.chargingState] || '?';
                const rtChargingLabel = chargingStateMap[realtime.chargingState] || '?';
                const connectLabel = connectStateMap[data.connectState] || '?';
                const rtConnectLabel = connectStateMap[realtime.connectState] || '?';
                const rtChargeLabel = chargeStateMap[realtime.chargeState] || '?';

                this.log.info(`=== SOC COMPARISON for ${vin} ===`);
                this.log.info(`Realtime elecPercent:    ${realtime.elecPercent}`);
                this.log.info(`Charging soc:            ${chargingSoc}`);
                this.log.info(`SOC Difference:          ${chargingSoc - realtime.elecPercent}`);
                this.log.info(`---`);
                this.log.info(`Realtime chargeState:    ${realtime.chargeState} (${rtChargeLabel})`);
                this.log.info(`Charging chargingState:  ${data.chargingState} (${chargingLabel})`);
                this.log.info(`---`);
                this.log.info(`Realtime chargingState:  ${realtime.chargingState} (${rtChargingLabel})`);
                this.log.info(`Realtime connectState:   ${realtime.connectState} (${rtConnectLabel})`);
                this.log.info(`Charging connectState:   ${data.connectState} (${connectLabel})`);
                this.log.info(`---`);
                this.log.info(`Realtime remaining:      ${realtime.remainingHours}h ${realtime.remainingMinutes}m`);
                this.log.info(`Charging fullHour/Min:   ${data.fullHour}h ${data.fullMinute}m`);
                this.log.info(`================================`);
            } else if (bydapi.isEndpointNotSupported(decoded.code)) {
                this.log.info(`Charging endpoint not supported for ${vin}`);
            } else {
                this.log.warn(`Charging comparison failed: code=${decoded.code}`);
            }
        } catch (error) {
            this.log.error(`Charging comparison error: ${error.message}`);
        }
    }

    async connectMqtt() {
        if (!this.session) {
            return;
        }

        // Fetch MQTT broker address
        const req = bydapi.buildEmqBrokerRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
        );

        await this.requestClient({
            method: 'post',
            url: `${bydapi.BASE_URL}/app/emqAuth/getEmqBrokerIp`,
            headers: {
                'User-Agent': bydapi.USER_AGENT,
                'Content-Type': 'application/json; charset=UTF-8',
            },
            data: { request: bydapi.encodeEnvelope(req.outer) },
        })
            .then(async res => {
                // this.log.debug(`EMQ broker response: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);

                if (decoded.code !== '0') {
                    this.log.error(`EMQ broker lookup failed: code=${decoded.code} message=${decoded.message || ''}`);
                    return;
                }

                const data = bydapi.decryptResponseData(decoded.respondData, req.contentKey);
                this.log.debug(`EMQ broker data: ${JSON.stringify(data)}`);
                // Response contains emqBorker (typo in API) or emqBroker
                this.mqttBroker = data.emqBorker || data.emqBroker;
                this.log.debug(`MQTT broker: ${this.mqttBroker}`);
            })
            .catch(error => {
                this.log.error(`EMQ broker error: ${error.message}`);
            });

        if (!this.mqttBroker) {
            this.log.warn('Could not get MQTT broker address');
            return;
        }

        // Build MQTT credentials
        const clientId = bydapi.buildMqttClientId(this.deviceConfig.imeiMd5);
        const tsSeconds = Math.floor(Date.now() / 1000);
        const mqttPassword = bydapi.buildMqttPassword(this.session, clientId, tsSeconds);
        const topic = `oversea/res/${this.session.userId}`;

        this.log.info(`Connecting to MQTT broker: ${this.mqttBroker}`);

        // Connect to MQTT broker
        this.mqttClient = mqtt.connect(`mqtts://${this.mqttBroker}`, {
            clientId,
            username: this.session.userId,
            password: mqttPassword,
            protocolVersion: 5,
            rejectUnauthorized: true,
            reconnectPeriod: 30000,
            connectTimeout: 30000,
        });

        this.mqttClient.on('connect', () => {
            this.log.info('MQTT connected');
            this.mqttClient.subscribe(topic, { qos: 1 }, err => {
                if (err) {
                    this.log.error(`MQTT subscribe error: ${err.message}`);
                } else {
                    this.log.info(`MQTT subscribed to: ${topic}`);
                }
            });
        });

        this.mqttClient.on('message', (msgTopic, message) => {
            this.handleMqttMessage(msgTopic, message);
        });

        this.mqttClient.on('error', err => {
            this.log.error(`MQTT error: ${err.message}`);
        });

        this.mqttClient.on('close', () => {
            this.log.debug('MQTT connection closed');
        });

        this.mqttClient.on('reconnect', () => {
            this.log.debug('MQTT reconnecting...');
            // Update password on reconnect (timestamp changes)
            const newTsSeconds = Math.floor(Date.now() / 1000);
            const newPassword = bydapi.buildMqttPassword(this.session, clientId, newTsSeconds);
            this.mqttClient.options.password = newPassword;
        });
    }

    handleMqttMessage(topic, message) {
        try {
            const messageStr = message.toString();
            this.log.silly(`MQTT message on ${topic}: ${messageStr}`);

            // pyBYD approach: strip whitespace first, then always try to decrypt
            // MQTT messages are hex-encoded AES-encrypted payloads
            const stripped = messageStr.replace(/\s+/g, '');

            let payload;
            if (/^[0-9A-Fa-f]+$/.test(stripped) && this.session?.encryToken) {
                // Hex-encoded encrypted message
                try {
                    const decrypted = bydapi.decryptMqttPayload(stripped, this.session.encryToken);
                    payload = JSON.parse(decrypted);
                    this.log.debug(`MQTT decrypted: ${JSON.stringify(payload)}`);
                } catch (decryptError) {
                    // Decrypt failure often means stale encryToken - trigger re-auth (pyBYD pattern)
                    this.log.warn(`MQTT decrypt failed (${decryptError.message}), triggering re-auth`);
                    this.handleSessionExpired('decrypt_error', 'MQTT');
                    return;
                }
            } else {
                // Try to parse as plain JSON (fallback)
                try {
                    payload = JSON.parse(messageStr);
                } catch {
                    this.log.debug(`MQTT raw message (not hex, not JSON): ${messageStr.substring(0, 100)}`);
                    return;
                }
            }

            // pyBYD event types: "vehicleInfo", "remoteControl"
            // Payload structure: { "event": "vehicleInfo", "vin": "...", "data": { "respondData": {...} } }
            const eventType = payload.event || payload.type;
            const vin = payload.vin;

            if (!vin) {
                this.log.debug(`MQTT message without VIN: ${JSON.stringify(payload)}`);
                return;
            }

            if (eventType === 'vehicleInfo') {
                this.handleMqttVehicleInfo(vin, payload);
            } else if (eventType === 'remoteControl') {
                this.handleMqttRemoteControl(vin, payload);
            } else if (payload.data) {
                // Generic data update with wrapper
                this.log.info(`MQTT update for ${vin}: type=${eventType || 'unknown'}`);
                const respondData = payload.data?.respondData || payload.data;
                this.json2iob.parse(`${vin}.status.mqtt`, respondData, {
                    forceIndex: true,
                    descriptions,
                    states,
                });
            } else {
                // Direct data without wrapper
                this.log.debug(`MQTT generic message for ${vin}`);
                this.json2iob.parse(`${vin}.status.mqtt`, payload, {
                    forceIndex: true,
                    descriptions,
                    states,
                });
            }
        } catch (error) {
            this.log.error(`MQTT message handling error: ${error.message}`);
        }
    }

    /**
     * Handle MQTT vehicleInfo event - realtime vehicle data
     *
     * @param {string} vin - Vehicle VIN
     * @param {object} payload - MQTT payload
     */
    handleMqttVehicleInfo(vin, payload) {
        const respondData = payload.data?.respondData;
        if (!respondData || typeof respondData !== 'object') {
            this.log.debug(`MQTT vehicleInfo without respondData for ${vin}`);
            return;
        }

        this.log.info(`MQTT vehicleInfo update for ${vin}`);

        // Check if there's a pending waiter for this data (trigger+wait pattern)
        const requestSerial = respondData.requestSerial || payload.data?.requestSerial;
        if (requestSerial && this.pendingMqttWaiters.has(requestSerial)) {
            const waiter = this.pendingMqttWaiters.get(requestSerial);
            if (waiter.type === 'vehicleInfo' && waiter.vin === vin) {
                this.log.debug(`MQTT vehicleInfo resolved waiter for ${vin} (serial: ${requestSerial})`);
                waiter.resolve(respondData);
                return; // Waiter will handle the data processing
            }
        }

        // No waiter - process directly (push notification from car)
        this.processRealtimeData(vin, respondData);
    }

    /**
     * Handle MQTT remoteControl event - command result
     *
     * @param {string} vin - Vehicle VIN
     * @param {object} payload - MQTT payload
     */
    handleMqttRemoteControl(vin, payload) {
        const respondData = payload.data?.respondData;
        if (!respondData || typeof respondData !== 'object') {
            this.log.debug(`MQTT remoteControl without respondData for ${vin}`);
            return;
        }

        // GPS trigger response has different structure: {res: 2, data: {latitude, longitude, ...}}
        if (respondData.res !== undefined && respondData.data?.latitude !== undefined) {
            this.log.debug(
                `MQTT GPS response for ${vin}: lat=${respondData.data.latitude}, lon=${respondData.data.longitude}`,
            );

            // Check if there's a pending GPS waiter
            const requestSerial = respondData.requestSerial || payload.data?.uuid;
            if (requestSerial && this.pendingMqttWaiters.has(requestSerial)) {
                const waiter = this.pendingMqttWaiters.get(requestSerial);
                if (waiter.type === 'gps' && waiter.vin === vin) {
                    this.log.debug(`MQTT GPS resolved waiter for ${vin} (serial: ${requestSerial})`);
                    waiter.resolve(respondData);
                    return;
                }
            }

            // No waiter - process directly
            this.processGpsData(vin, respondData);
            return;
        }

        // Derive correlation serial (pyBYD: respondData.requestSerial || data.uuid)
        const requestSerial = respondData.requestSerial || payload.data?.uuid;
        const commandType = respondData.commandType || payload.data?.commandType;
        const message = respondData.message || respondData.msg;

        // Determine success from controlState or res field
        // controlState: 0=pending, 1=success, 2=failure
        // res: 2=success, other=failure (pyBYD: res=2 → controlState=1)
        let controlState = respondData.controlState;
        if (controlState === undefined && respondData.res !== undefined) {
            // Convert res format to controlState (pyBYD logic)
            controlState = respondData.res === 2 ? 1 : 2;
        }

        const success = controlState === 1;
        const failed = controlState === 2;
        const statusText = controlState === 0 ? 'pending' : controlState === 1 ? 'success' : 'failure';
        const msgSuffix = message ? ` (${message})` : '';

        this.log.info(
            `MQTT remoteControl for ${vin}: ${commandType || requestSerial || 'unknown'} = ${statusText}${msgSuffix}`,
        );

        // Resolve pending waiter if we have a requestSerial match
        if (requestSerial && this.pendingRemoteControls.has(requestSerial)) {
            const pending = this.pendingRemoteControls.get(requestSerial);
            this.pendingRemoteControls.delete(requestSerial);

            if (success || failed) {
                // Terminal state - resolve the waiter
                this.log.debug(`MQTT resolved pending command ${requestSerial}: ${statusText}`);
                pending.resolve({
                    success,
                    controlState,
                    message,
                    commandType,
                    source: 'mqtt',
                });
            }
        } else if (!requestSerial && (success || failed)) {
            // No requestSerial in MQTT - try to match by VIN (last pending for this VIN)
            for (const [serial, pending] of this.pendingRemoteControls.entries()) {
                if (pending.vin === vin) {
                    this.pendingRemoteControls.delete(serial);
                    this.log.debug(`MQTT resolved pending command by VIN ${vin}: ${statusText}`);
                    pending.resolve({
                        success,
                        controlState,
                        message,
                        commandType,
                        source: 'mqtt',
                    });
                    break;
                }
            }
        }

        // Update HVAC state if climate command completed successfully (flat structure)
        if (success && commandType) {
            const cmdUpper = String(commandType).toUpperCase();
            if (cmdUpper === 'CLOSEAIR') {
                this.setStateAsync(`${vin}.status.status`, 0, true).catch(() => {});
                this.setStateAsync(`${vin}.status.acSwitch`, 0, true).catch(() => {});
            } else if (cmdUpper === 'OPENAIR') {
                this.setStateAsync(`${vin}.status.status`, 2, true).catch(() => {});
            }
        }
    }

    /**
     * Wait for MQTT remote control result with timeout
     *
     * @param {string} requestSerial - Request serial from HTTP trigger
     * @param {string} vin - Vehicle VIN
     * @param {string} commandType - Command type for logging
     * @returns {Promise<object|null>} Result or null on timeout
     */
    waitForMqttResult(requestSerial, vin, commandType) {
        if (!this.mqttClient || !requestSerial) {
            return Promise.resolve(null);
        }

        return new Promise(resolve => {
            const timeout = setTimeout(() => {
                if (this.pendingRemoteControls.has(requestSerial)) {
                    this.pendingRemoteControls.delete(requestSerial);
                    this.log.debug(`MQTT timeout for ${commandType} (${requestSerial}), falling back to HTTP`);
                    resolve(null);
                }
            }, this.mqttWaitTimeout);

            this.pendingRemoteControls.set(requestSerial, {
                resolve: result => {
                    clearTimeout(timeout);
                    resolve(result);
                },
                vin,
                commandType,
                timestamp: Date.now(),
            });
        });
    }

    /**
     * Verify control password (PIN) for remote commands
     * Call this before first remote command to check if PIN is valid
     *
     * @param {string} vin - Vehicle identification number
     */
    async verifyControlPassword(vin) {
        if (!this.session) {
            return { success: false, error: 'No session' };
        }

        if (!this.config.controlPin) {
            this.log.error('Control PIN not configured - please set in adapter settings');
            return { success: false, error: 'No control PIN configured' };
        }

        const req = bydapi.buildVerifyControlPasswordRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
            this.config.controlPin,
        );

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/vehicle/vehicleswitch/verifyControlPassword`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(req.outer) },
            });

            this.log.debug(`Verify control password response: ${JSON.stringify(res.data)}`);
            this.log.debug(`contentKey: ${req.contentKey}, encryToken: ${this.session.encryToken}`);
            const decoded = bydapi.decodeEnvelope(res.data);
            this.log.debug(`Verify control password decoded: ${JSON.stringify(decoded)}`);

            if (decoded.code !== '0') {
                if (bydapi.isNoPinSetError(decoded.code)) {
                    // 5011: No PIN set in BYD app - this is a user setup issue
                    const errMsg = bydapi.getControlPasswordErrorMessage(decoded.code);
                    this.log.error(`Control PIN verification failed: ${errMsg}`);
                    this.log.error('You must first set a Remote Control Password in the BYD app');
                    this.log.error('BYD App > Settings > Security > Remote Control Password');
                    return { success: false, error: errMsg, noPinInApp: true };
                }
                if (bydapi.isControlPasswordError(decoded.code)) {
                    const errMsg = bydapi.getControlPasswordErrorMessage(decoded.code);
                    this.log.error(`Control PIN verification failed: ${errMsg}`);
                    return { success: false, error: errMsg };
                }
                this.log.error(`Control PIN verification failed: code=${decoded.code}`);
                return { success: false, error: `API error: ${decoded.code}` };
            }

            if (decoded.respondData) {
                try {
                    const data = bydapi.decryptResponseData(decoded.respondData, req.contentKey);
                    this.log.debug(`Control password verification result: ${JSON.stringify(data)}`);
                    if (data.ok === true) {
                        this.log.info('Control password verified successfully');
                        return { success: true };
                    }
                } catch (decryptErr) {
                    this.log.debug(`Failed to decrypt respondData: ${decryptErr.message}`);
                    // Some responses don't have encrypted respondData, treat code=0 as success
                }
            }

            // code=0 without respondData or failed decrypt = success
            this.log.info('Control password verified (code=0)');
            return { success: true };
        } catch (error) {
            this.log.error(`Control password verification error: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    /**
     * Toggle smart charging on/off
     *
     * @param {string} vin - Vehicle identification number
     * @param {boolean} enable - True to enable, false to disable
     */
    async toggleSmartCharging(vin, enable) {
        if (!this.session) {
            return { success: false, error: 'No session' };
        }

        const req = bydapi.buildSmartChargingToggleRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
            enable,
        );

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/smartCharge/changeChargeStatue`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(req.outer) },
            });

            // this.log.debug(`Smart charging toggle response: ${JSON.stringify(res.data)}`);
            const decoded = bydapi.decodeEnvelope(res.data);
            this.log.debug(`Decoded smart charging toggle: ${JSON.stringify(decoded)}`);
            if (decoded.code !== '0') {
                this.log.error(`Smart charging toggle failed: code=${decoded.code}`);
                return { success: false, error: `API error: ${decoded.code}` };
            }

            this.log.info(`Smart charging ${enable ? 'enabled' : 'disabled'} successfully`);
            return { success: true };
        } catch (error) {
            this.log.error(`Smart charging toggle error: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    /**
     * Save smart charging schedule
     *
     * @param {string} vin - Vehicle identification number
     * @param {number} targetSoc - Target state of charge (0-100)
     * @param {number} startHour - Start hour (0-23)
     * @param {number} startMinute - Start minute (0-59)
     * @param {number} endHour - End hour (0-23)
     * @param {number} endMinute - End minute (0-59)
     */
    async saveChargingSchedule(vin, targetSoc, startHour, startMinute, endHour, endMinute) {
        if (!this.session) {
            return { success: false, error: 'No session' };
        }

        const req = bydapi.buildSmartChargingScheduleRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
            targetSoc,
            startHour,
            startMinute,
            endHour,
            endMinute,
        );

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/smartCharge/saveOrUpdate`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(req.outer) },
            });

            //  this.log.debug(`Charging schedule save response: ${JSON.stringify(res.data)}`);
            const decoded = bydapi.decodeEnvelope(res.data);
            this.log.debug(`Decoded charging schedule save: ${JSON.stringify(decoded)}`);
            if (decoded.code !== '0') {
                this.log.error(`Charging schedule save failed: code=${decoded.code}`);
                return { success: false, error: `API error: ${decoded.code}` };
            }

            this.log.info(
                `Charging schedule saved: ${startHour}:${startMinute} - ${endHour}:${endMinute}, target SOC ${targetSoc}%`,
            );
            return { success: true };
        } catch (error) {
            this.log.error(`Charging schedule save error: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    /**
     * Send remote control command with MQTT-first pattern
     * 1. Trigger via HTTP, get requestSerial
     * 2. Wait for MQTT result (8s timeout)
     * 3. Fall back to HTTP polling only if MQTT times out
     *
     * @param {string} vin - Vehicle VIN
     * @param {string} commandType - Command type (LOCKDOOR, OPENDOOR, etc.)
     * @param {object|null} controlParamsMap - Optional command parameters
     * @param {number} retryCount - Internal retry counter
     */
    async sendRemoteControl(vin, commandType, controlParamsMap = null, retryCount = 0) {
        if (!this.session) {
            return { success: false, error: 'No session' };
        }

        const MAX_RATE_LIMIT_RETRIES = 3;
        const RATE_LIMIT_DELAY_MS = 5000;

        // Step 1: Trigger remote control via HTTP
        const triggerReq = bydapi.buildRemoteControlRequest(
            this.session,
            this.config.countryCode,
            this.config.language,
            this.deviceConfig,
            vin,
            commandType,
            controlParamsMap,
            this.config.controlPin || null,
        );

        let requestSerial = null;
        let triggerError = null;

        try {
            const res = await this.requestClient({
                method: 'post',
                url: `${bydapi.BASE_URL}/control/remoteControl`,
                headers: {
                    'User-Agent': bydapi.USER_AGENT,
                    'Content-Type': 'application/json; charset=UTF-8',
                },
                data: { request: bydapi.encodeEnvelope(triggerReq.outer) },
            });

            //  this.log.debug(`Remote control trigger response: ${JSON.stringify(res.data)}`);
            const decoded = bydapi.decodeEnvelope(res.data);
            // this.log.debug(`Decoded remote control trigger: ${JSON.stringify(decoded)}`);
            if (decoded.code !== '0') {
                // Handle specific error codes
                if (bydapi.isControlPasswordError(decoded.code)) {
                    const errMsg = bydapi.getControlPasswordErrorMessage(decoded.code);
                    this.log.error(`Remote control failed: ${errMsg}`);
                    return { success: false, error: errMsg };
                }

                if (bydapi.isRateLimited(decoded.code)) {
                    if (retryCount < MAX_RATE_LIMIT_RETRIES) {
                        this.log.warn(`Rate limited, retry ${retryCount + 1}/${MAX_RATE_LIMIT_RETRIES}`);
                        await this.sleep(RATE_LIMIT_DELAY_MS);
                        return this.sendRemoteControl(vin, commandType, controlParamsMap, retryCount + 1);
                    }
                    return { success: false, error: 'Rate limit exceeded' };
                }

                if (bydapi.isSessionExpired(decoded.code)) {
                    this.log.warn('Session expired, re-authenticating...');
                    this.log.debug(`DEBUG: Setting session=null in sendRemoteControl (code=${decoded.code})`);
                    this.session = null;
                    await this.login();
                    if (this.session && retryCount < 1) {
                        return this.sendRemoteControl(vin, commandType, controlParamsMap, retryCount + 1);
                    }
                    return { success: false, error: 'Session expired' };
                }

                if (bydapi.isRemoteControlServiceError(decoded.code)) {
                    this.log.error(`Remote control failed (1009): Vehicle offline or T-Box not responding`);
                    return { success: false, error: 'Vehicle unreachable (1009)' };
                }

                triggerError = `API error: ${decoded.code}`;
            } else if (decoded.respondData) {
                const data = bydapi.decryptResponseData(decoded.respondData, triggerReq.contentKey);
                this.log.debug(`Remote control trigger data: ${JSON.stringify(data)}`);
                requestSerial = data.requestSerial || null;
                this.log.debug(`Remote control triggered, requestSerial: ${requestSerial}`);
            }
        } catch (error) {
            this.log.error(`Remote control trigger error: ${error.message}`);
            return { success: false, error: error.message };
        }

        if (triggerError) {
            this.log.error(`Remote control failed: ${triggerError}`);
            return { success: false, error: triggerError };
        }

        if (!requestSerial) {
            this.log.warn('No requestSerial received from trigger');
            return { success: false, error: 'No requestSerial' };
        }

        // Step 2: Wait for MQTT result (MQTT-first pattern)
        this.log.debug(`Waiting for MQTT result (${this.mqttWaitTimeout}ms timeout)...`);
        const mqttResult = await this.waitForMqttResult(requestSerial, vin, commandType);

        if (mqttResult) {
            // Got result via MQTT - fast path!
            this.log.info(`Remote control ${commandType}: ${mqttResult.success ? 'success' : 'failed'} (via MQTT)`);
            return mqttResult;
        }

        // Step 3: MQTT timeout - fall back to HTTP polling
        this.log.debug('MQTT timeout, falling back to HTTP polling...');
        return this.pollRemoteControlResult(vin, commandType, requestSerial, triggerReq.contentKey);
    }

    /**
     * Poll for remote control result via HTTP (fallback when MQTT times out)
     *
     * @param {string} vin - Vehicle VIN
     * @param {string} commandType - Command type
     * @param {string} requestSerial - Request serial from trigger
     * @param {string} contentKey - Content key for decryption
     */
    async pollRemoteControlResult(vin, commandType, requestSerial, contentKey) {
        const MAX_POLL_ATTEMPTS = 10;
        const POLL_INTERVAL_MS = 1500;

        for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
            await this.sleep(POLL_INTERVAL_MS);

            const pollReq = bydapi.buildRemoteControlRequest(
                this.session,
                this.config.countryCode,
                this.config.language,
                this.deviceConfig,
                vin,
                commandType,
                null,
                null,
                requestSerial,
            );

            try {
                const res = await this.requestClient({
                    method: 'post',
                    url: `${bydapi.BASE_URL}/control/remoteControlResult`,
                    headers: {
                        'User-Agent': bydapi.USER_AGENT,
                        'Content-Type': 'application/json; charset=UTF-8',
                    },
                    data: { request: bydapi.encodeEnvelope(pollReq.outer) },
                });

                this.log.debug(`Remote control poll ${attempt + 1}/${MAX_POLL_ATTEMPTS}: ${JSON.stringify(res.data)}`);
                const decoded = bydapi.decodeEnvelope(res.data);

                if (decoded.code === '0' && decoded.respondData) {
                    const data = bydapi.decryptResponseData(decoded.respondData, pollReq.contentKey || contentKey);

                    if (bydapi.isRemoteControlReady(data)) {
                        const controlState = parseInt(data.controlState, 10);
                        const success = controlState === 1;
                        const statusText = success ? 'success' : 'failed';

                        this.log.info(`Remote control ${commandType}: ${statusText} (via HTTP poll)`);
                        return {
                            success,
                            controlState,
                            message: data.message || data.msg,
                            source: 'http',
                        };
                    }
                }
            } catch (error) {
                this.log.debug(`Poll attempt ${attempt + 1} error: ${error.message}`);
            }
        }

        this.log.warn(`Remote control ${commandType}: timeout after ${MAX_POLL_ATTEMPTS} poll attempts`);
        return { success: false, error: 'Polling timeout' };
    }

    async onStateChange(id, state) {
        if (!state) {
            return;
        }

        const deviceId = id.split('.')[2];
        const folder = id.split('.')[3];
        const subPath = id.split('.').slice(4).join('.');

        // Mapping: status path -> { remote, transform }
        // When status changes with ack=true, update corresponding remote state
        // Flat structure - all fields directly under status.*
        const statusToRemoteMap = {
            status: { remote: 'climate', transform: v => v === 2 }, // HVAC status field
            batteryHeatState: { remote: 'batteryHeat', transform: v => v > 0 },
            mainSeatHeatState: { remote: 'seatHeat', transform: v => v > 0 },
            leftFrontDoorLock: { remote: 'lock', transform: v => v === 2 },
        };

        // Handle ack=true status changes -> update remote states
        if (state.ack && folder === 'status') {
            const mapping = statusToRemoteMap[subPath];
            if (mapping) {
                const boolVal = mapping.transform(state.val);
                await this.setStateAsync(`${deviceId}.remote.${mapping.remote}`, boolVal, true);
                this.log.debug(`Status ${subPath}=${state.val} -> remote.${mapping.remote}=${boolVal}`);
            }
            return;
        }

        // Handle ack===true for remote states (ignore)
        if (state.ack && folder === 'remote') {
            return;
        }

        const command = id.split('.')[4];

        // Handle ack===false for commands
        if (!state.ack && folder === 'remote') {
            this.log.debug(
                `DEBUG onStateChange: id=${id}, val=${state.val}, ack=${state.ack}, ts=${state.ts}, lc=${state.lc}`,
            );

            if (command === 'refresh') {
                // Ignore if value is not true (button press)
                if (state.val !== true) {
                    this.log.debug(`DEBUG refresh ignored: val=${state.val} (not true)`);
                    return;
                }
                this.log.info(`Manual refresh requested for ${deviceId}`);
                this.log.debug(`DEBUG refresh: session=${this.session ? 'exists' : 'null'}`);
                if (!this.session) {
                    this.log.warn('No session - attempting re-login before refresh');
                    await this.login();
                    this.log.debug(`DEBUG refresh after login: session=${this.session ? 'exists' : 'null'}`);
                }
                if (!this.session) {
                    this.log.error('Still no session after re-login attempt');
                    return;
                }
                this.log.debug(`DEBUG refresh: calling updateSingleVehicle`);
                await this.updateSingleVehicle(deviceId);
                this.log.debug(`DEBUG refresh: updateSingleVehicle done`);
                return;
            }

            // Climate uses different format with commandType and controlParamsMap
            if (command === 'climate') {
                this.log.info(`Sending climate command: ${state.val ? 'ON' : 'OFF'} for ${deviceId}`);

                if (state.val) {
                    // Climate ON - use helper for params
                    const controlParamsMap = bydapi.buildClimateParams({
                        temp: 7, // 21°C (scale 1-17 = 15-31°C)
                        copilotTemp: 7,
                        timeSpan: 1, // 10 minutes
                        airConditioningMode: 1,
                    });
                    await this.sendRemoteControl(deviceId, 'OPENAIR', controlParamsMap);
                } else {
                    // Climate OFF
                    const controlParamsMap = bydapi.buildClimateParams({
                        temp: 7,
                        copilotTemp: 7,
                        timeSpan: 0,
                        airConditioningMode: 0,
                    });
                    await this.sendRemoteControl(deviceId, 'CLOSEAIR', controlParamsMap);
                }

                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(() => {
                    this.updateVehicles();
                }, 10 * 1000);
                return;
            }

            // Seat heating uses VENTILATIONHEATING commandType
            if (command === 'seatHeat') {
                this.log.info(`Sending seat heating command: ${state.val ? 'ON' : 'OFF'} for ${deviceId}`);

                const controlParamsMap = bydapi.buildSeatClimateParams({
                    mainHeat: state.val ? 3 : 0,
                    copilotHeat: state.val ? 3 : 0,
                    steeringWheelHeat: state.val ? 1 : 0,
                });
                await this.sendRemoteControl(deviceId, 'VENTILATIONHEATING', controlParamsMap);

                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(() => {
                    this.updateVehicles();
                }, 10 * 1000);
                return;
            }

            // Battery heating uses BATTERYHEAT commandType
            if (command === 'batteryHeat') {
                this.log.info(`Sending battery heating command: ${state.val ? 'ON' : 'OFF'} for ${deviceId}`);

                const controlParamsMap = bydapi.buildBatteryHeatParams(state.val);
                await this.sendRemoteControl(deviceId, 'BATTERYHEAT', controlParamsMap);

                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(() => {
                    this.updateVehicles();
                }, 10 * 1000);
                return;
            }

            // Verify control PIN (manual trigger)
            if (command === 'verifyPin') {
                if (state.val) {
                    this.log.info(`Verifying control PIN for ${deviceId}`);
                    const result = await this.verifyControlPassword(deviceId);
                    if (result.success) {
                        this.log.info('Control PIN verified successfully');
                    } else {
                        this.log.error(`Control PIN verification failed: ${result.error}`);
                    }
                }
                return;
            }

            // Lock toggle: true=lock, false=unlock
            if (command === 'lock') {
                const commandType = state.val ? 'LOCKDOOR' : 'OPENDOOR';
                this.log.info(`Sending lock command: ${state.val ? 'LOCK' : 'UNLOCK'} for ${deviceId}`);
                await this.sendRemoteControl(deviceId, commandType);
                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(() => {
                    this.updateVehicles();
                }, 10 * 1000);
                return;
            }

            // Commands using commandType (no controlParamsMap needed)
            const commandTypeMap = {
                flash: 'FLASHLIGHTNOWHISTLE',
                findCar: 'FINDCAR',
                closeWindows: 'CLOSEWINDOW',
            };

            const commandType = commandTypeMap[command];
            if (!commandType) {
                this.log.warn(`Unknown command: ${command}`);
                return;
            }

            this.log.info(`Sending remote command: ${command} (${commandType}) for ${deviceId}`);

            await this.sendRemoteControl(deviceId, commandType);

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
            this.telemetryInterval && clearInterval(this.telemetryInterval);
            this.gpsInterval && clearInterval(this.gpsInterval);
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            if (this.mqttClient) {
                this.mqttClient.end(true);
                this.mqttClient = null;
            }
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
