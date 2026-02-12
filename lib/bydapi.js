'use strict';

const crypto = require('crypto');
const bangcle = require('./bangcle');

const BASE_URL = 'https://dilinkappoversea-eu.byd.auto';
const USER_AGENT = 'okhttp/4.12.0';

// Session expired error codes - trigger re-authentication
const SESSION_EXPIRED_CODES = new Set(['1005', '1010']);

// Rate limit error code - command in progress or too many requests
const RATE_LIMIT_CODE = '6024';

// Control password error codes
const CONTROL_PASSWORD_ERRORS = {
    '5005': 'Wrong control password',
    '5006': 'Control password locked for today (too many attempts)',
};

// Endpoint not supported
const ENDPOINT_NOT_SUPPORTED_CODE = '1001';

const DEFAULT_DEVICE_CONFIG = Object.freeze({
    imeiMd5: '00000000000000000000000000000000',
    networkType: 'wifi',
    appInnerVersion: '322',
    appVersion: '3.2.2',
    osType: '15',
    osVersion: '35',
    timeZone: 'Europe/Amsterdam',
    deviceType: '0',
    mobileBrand: 'XIAOMI',
    mobileModel: 'POCO F1',
    softType: '0',
    tboxVersion: '3',
    isAuto: '1',
    ostype: 'and',
    imei: 'BANGCLE01234',
    mac: '00:00:00:00:00:00',
    model: 'POCO F1',
    sdk: '35',
    mod: 'Xiaomi',
});

// Crypto helpers
function md5Hex(value) {
    return crypto.createHash('md5').update(value, 'utf8').digest('hex').toUpperCase();
}

function pwdLoginKey(password) {
    return md5Hex(md5Hex(password));
}

function sha1Mixed(value) {
    const digest = crypto.createHash('sha1').update(value, 'utf8').digest();
    const mixed = Array.from(digest)
        .map((byte, index) => {
            const hex = byte.toString(16).padStart(2, '0');
            return index % 2 === 0 ? hex.toUpperCase() : hex.toLowerCase();
        })
        .join('');

    let filtered = '';
    for (let i = 0; i < mixed.length; i += 1) {
        const ch = mixed[i];
        if (ch === '0' && i % 2 === 0) {
            continue;
        }
        filtered += ch;
    }
    return filtered;
}

function buildSignString(fields, password) {
    const keys = Object.keys(fields).sort();
    const joined = keys.map(key => `${key}=${String(fields[key])}`).join('&');
    return `${joined}&password=${password}`;
}

function computeCheckcode(payload) {
    const json = JSON.stringify(payload);
    const md5 = crypto.createHash('md5').update(json, 'utf8').digest('hex');
    return `${md5.slice(24, 32)}${md5.slice(8, 16)}${md5.slice(16, 24)}${md5.slice(0, 8)}`;
}

function aesEncryptHex(plaintextUtf8, keyHex) {
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.alloc(16, 0);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    return Buffer.concat([cipher.update(plaintextUtf8, 'utf8'), cipher.final()])
        .toString('hex')
        .toUpperCase();
}

function aesDecryptUtf8(cipherHex, keyHex) {
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.alloc(16, 0);
    const ciphertext = Buffer.from(cipherHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function randomHex16() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

// Bangcle envelope
/**
 *
 */
function encodeEnvelope(payload) {
    return bangcle.encodeEnvelope(JSON.stringify(payload));
}

/**
 *
 */
function decodeEnvelope(rawPayload) {
    // Handle response object with 'response' field
    const payload = typeof rawPayload === 'object' && rawPayload.response ? rawPayload.response : rawPayload;

    if (typeof payload !== 'string' || !payload.trim()) {
        throw new Error('Empty response payload');
    }
    const decodedText = bangcle.decodeEnvelope(payload).toString('utf8').trim();
    const normalised =
        decodedText.startsWith('F{') || decodedText.startsWith('F[') ? decodedText.slice(1) : decodedText;
    return JSON.parse(normalised);
}

/**
 *
 */
function decryptResponseData(respondDataHex, keyHex) {
    const plain = aesDecryptUtf8(respondDataHex, keyHex);
    return JSON.parse(plain);
}

// Common fields for all requests
function commonOuterFields(deviceConfig) {
    return {
        ostype: deviceConfig.ostype,
        imei: deviceConfig.imei,
        mac: deviceConfig.mac,
        model: deviceConfig.model,
        sdk: deviceConfig.sdk,
        mod: deviceConfig.mod,
    };
}

// Build login request
// Sample Response (decrypted respondData):
// {
//   "token": {
//     "userId": "1234567890123456789",
//     "signToken": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
//     "encryToken": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
//     "accessToken": "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
//   },
//   "user": { "nickname": "User", "email": "user@example.com", "phone": "", "countryCode": "AT" },
//   "securityInfo": { "isPwdSet": 1, "isGesturePwdSet": 0 }
// }
/**
 *
 */
function buildLoginRequest(username, password, countryCode, language, deviceConfig) {
    const nowMs = Date.now();
    const random = randomHex16();
    const reqTimestamp = String(nowMs);
    const serviceTime = String(Date.now());

    const inner = {
        appInnerVersion: deviceConfig.appInnerVersion,
        appVersion: deviceConfig.appVersion,
        deviceName: `${deviceConfig.mobileBrand}${deviceConfig.mobileModel}`,
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        isAuto: deviceConfig.isAuto,
        mobileBrand: deviceConfig.mobileBrand,
        mobileModel: deviceConfig.mobileModel,
        networkType: deviceConfig.networkType,
        osType: deviceConfig.osType,
        osVersion: deviceConfig.osVersion,
        random,
        softType: deviceConfig.softType,
        timeStamp: reqTimestamp,
        timeZone: deviceConfig.timeZone,
    };

    const encryData = aesEncryptHex(JSON.stringify(inner), pwdLoginKey(password));

    const signFields = {
        ...inner,
        countryCode,
        functionType: 'pwdLogin',
        identifier: username,
        identifierType: '0',
        language,
        reqTimestamp,
    };

    const sign = sha1Mixed(buildSignString(signFields, md5Hex(password)));

    const outer = {
        countryCode,
        encryData,
        functionType: 'pwdLogin',
        identifier: username,
        identifierType: '0',
        imeiMD5: deviceConfig.imeiMd5,
        isAuto: deviceConfig.isAuto,
        language,
        reqTimestamp,
        sign,
        signKey: password,
        ...commonOuterFields(deviceConfig),
        serviceTime,
    };
    outer.checkcode = computeCheckcode(outer);

    return { outer };
}

// Build token-based request envelope
function buildTokenEnvelope(session, countryCode, language, deviceConfig, inner) {
    const nowMs = Date.now();
    const reqTimestamp = String(nowMs);
    const contentKey = md5Hex(session.encryToken);
    const signKey = md5Hex(session.signToken);
    const encryData = aesEncryptHex(JSON.stringify(inner), contentKey);

    const signFields = {
        ...inner,
        countryCode,
        identifier: session.userId,
        imeiMD5: deviceConfig.imeiMd5,
        language,
        reqTimestamp,
    };
    const sign = sha1Mixed(buildSignString(signFields, signKey));

    const outer = {
        countryCode,
        encryData,
        identifier: session.userId,
        imeiMD5: deviceConfig.imeiMd5,
        language,
        reqTimestamp,
        sign,
        ...commonOuterFields(deviceConfig),
        serviceTime: String(Date.now()),
    };
    outer.checkcode = computeCheckcode(outer);

    return { outer, contentKey };
}

// Build vehicle list request
// Sample Response (decrypted respondData) - array of vehicles:
// [{
//   "vin": "LGXXXXXXXXXXX00000", "autoAlias": "BYD SEALION 7", "autoPlate": "AB123CD",
//   "brandName": "BYD", "modelName": "BYD SEALION 7", "modelId": 28,
//   "totalMileage": 13060, "energyType": "0", "carType": 0,
//   "defaultCar": 1, "permissionStatus": 3, "tboxVersion": "3",
//   "vehicleState": "0", "vehicleTimeZone": "Europe/Vienna",
//   "autoBoughtTime": 1742770800000, "yunActiveTime": 1742770800000,
//   "cfPic": { "picMainUrl": "https://...", "picSetUrl": "https://..." },
//   "vehicleFunLearnInfo": {
//     "bookingCharge": 2, "batteryHeating": 1, "steeringWheelHeating": 1,
//     "openWindowLearnInfo": 1, "trunkLearnInfo": 1, "gpsLearnInfo": 1
//   },
//   "rangeDetailList": [{ "code": "2", "name": "Schlüssel und Steuerung", ... }]
// }]
/**
 *
 */
function buildVehicleListRequest(session, countryCode, language, deviceConfig) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build vehicle realtime request
// Sample Response (decrypted respondData):
// {
//   "requestSerial": "20250612000000000012345678",
//   "vin": "LGXXXXXXXXXXX00000",
//   "soc": "75", "enduranceMileage": "320", "totalMileage": "13060",
//   "leftFrontTirepressure": "253", "rightFrontTirepressure": "250",
//   "leftRearTirepressure": "248", "rightRearTirepressure": "251",
//   "leftFrontTireTemperature": "-127", "rightFrontTireTemperature": "-127",
//   "leftRearTireTemperature": "-127", "rightRearTireTemperature": "-127",
//   "leftFrontDoorStatus": "2", "rightFrontDoorStatus": "2",
//   "leftRearDoorStatus": "2", "rightRearDoorStatus": "2",
//   "leftFrontWindowStatus": "2", "rightFrontWindowStatus": "2",
//   "leftRearWindowStatus": "2", "rightRearWindowStatus": "2",
//   "sunRoofStatus": "2", "engineSt": "0", "bonnetStatus": "2",
//   "bootStatus": "2", "doorLockStatus": "1", "chargeStatus": "0",
//   "onlineState": "1", "time": 1749732195000, "longitudeDone": "16.xxxxxx",
//   "latitudeDone": "48.xxxxxx", "altitude": "196", "heading": "123.45",
//   "airState": "0", "airTemp": "0", "cyclicFlag": "0", "defrostState": "0",
//   "remainChargingTime": "0", "timezoneOffset": "+02:00"
// }
/**
 *
 */
function buildVehicleRealtimeRequest(session, countryCode, language, deviceConfig, vin, requestSerial = null) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        energyType: '0',
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        tboxVersion: deviceConfig.tboxVersion,
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    if (requestSerial) {
        inner.requestSerial = requestSerial;
    }
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build GPS info request
// Sample Response (decrypted respondData):
// {
//   "requestSerial": "20250612000000000012345678",
//   "longitudeDone": "16.xxxxxx", "latitudeDone": "48.xxxxxx",
//   "altitude": "196", "speed": "0", "heading": "123.45",
//   "time": 1749732195000, "gpsState": "1"
// }
/**
 *
 */
function buildGpsInfoRequest(session, countryCode, language, deviceConfig, vin, requestSerial = null) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    if (requestSerial) {
        inner.requestSerial = requestSerial;
    }
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build remote control request
// CommandTypes: LOCKDOOR, OPENDOOR, FLASHLIGHTNOWHISTLE, FINDCAR, CLOSEWINDOW, OPENAIR, CLOSEAIR, VENTILATIONHEATING
// Sample Response (decrypted respondData):
// Trigger: { "requestSerial": "20250612000000000012345678" }
// Poll result: { "requestSerial": "...", "controlState": "1", "vin": "LGXXX..." }
// controlState: 0=pending, 1=success, 2=failed
/**
 *
 */
function buildRemoteControlRequest(
    session,
    countryCode,
    language,
    deviceConfig,
    vin,
    commandType,
    controlParamsMap = null,
    commandPwd = null,
    requestSerial = null,
) {
    // Base fields (from CommonRequestUtil.i())
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    // Command-specific fields (only added when present)
    if (commandType) {
        inner.commandType = commandType;
    }
    if (commandPwd) {
        // commandPwd must be MD5 hashed and uppercase hex encoded
        inner.commandPwd = crypto.createHash('md5').update(commandPwd, 'utf8').digest('hex').toUpperCase();
    }
    if (controlParamsMap) {
        // controlParamsMap must be JSON with sorted keys (like Python's sort_keys=True)
        if (typeof controlParamsMap === 'string') {
            inner.controlParamsMap = controlParamsMap;
        } else {
            const sorted = Object.keys(controlParamsMap).sort().reduce((obj, key) => {
                obj[key] = controlParamsMap[key];
                return obj;
            }, {});
            inner.controlParamsMap = JSON.stringify(sorted);
        }
    }
    if (requestSerial) {
        inner.requestSerial = requestSerial;
    }
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build energy consumption request
// Sample Response (decrypted respondData):
// {
//   "avgConsumption": "18.5", "avgConsumptionUnit": "kWh/100km",
//   "totalConsumption": "2405.2", "totalConsumptionUnit": "kWh",
//   "dailyList": [{ "date": "2025-02-10", "consumption": "12.3" }, ...]
// }
/**
 *
 */
function buildEnergyConsumptionRequest(session, countryCode, language, deviceConfig, vin) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build HVAC status request
// Endpoint: /control/getStatusNow
// Sample Response (decrypted respondData):
// {
//   "airState": "0", "airTemp": "22", "cyclicFlag": "0", "defrostState": "0",
//   "mainSeatHeat": "0", "copilotSeatHeat": "0", "steeringWheelHeat": "0"
// }
/**
 *
 */
function buildHvacStatusRequest(session, countryCode, language, deviceConfig, vin) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build charging status request
// Endpoint: /control/smartCharge/homePage
// Sample Response (decrypted respondData):
// {
//   "soc": "75", "chargeStatus": "0", "remainChargingTime": "0",
//   "chargingPower": "0", "estimatedRange": "320"
// }
/**
 *
 */
function buildChargingStatusRequest(session, countryCode, language, deviceConfig, vin) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Data readiness checks
/**
 *
 */
function isRealtimeDataReady(vehicleInfo) {
    if (!vehicleInfo || typeof vehicleInfo !== 'object') {
        return false;
    }
    if (Number(vehicleInfo.onlineState) === 2) {
        return false;
    }
    const tireFields = [
        'leftFrontTirepressure',
        'rightFrontTirepressure',
        'leftRearTirepressure',
        'rightRearTirepressure',
    ];
    if (tireFields.some(field => Number(vehicleInfo[field]) > 0)) {
        return true;
    }
    if (Number(vehicleInfo.time) > 0) {
        return true;
    }
    if (Number(vehicleInfo.enduranceMileage) > 0) {
        return true;
    }
    return false;
}

/**
 *
 */
function isGpsDataReady(gpsInfo) {
    if (!gpsInfo || typeof gpsInfo !== 'object') {
        return false;
    }
    const keys = Object.keys(gpsInfo);
    if (!keys.length || (keys.length === 1 && keys[0] === 'requestSerial')) {
        return false;
    }
    return true;
}

/**
 *
 */
function isRemoteControlReady(data) {
    if (!data || typeof data !== 'object') {
        return false;
    }
    // Check for controlState field indicating completion
    // 0 = pending, 1 = success, 2 = failed
    if (data.controlState !== undefined && data.controlState !== '0' && data.controlState !== 0) {
        return true;
    }
    // Check for result field
    if (data.result !== undefined) {
        return true;
    }
    return false;
}

// Helper to check if error code indicates session expired
function isSessionExpired(code) {
    return SESSION_EXPIRED_CODES.has(String(code));
}

// Helper to check if error code indicates rate limit
function isRateLimited(code) {
    return String(code) === RATE_LIMIT_CODE;
}

// Helper to check if error code indicates control password error
function isControlPasswordError(code) {
    return String(code) in CONTROL_PASSWORD_ERRORS;
}

// Get control password error message
function getControlPasswordErrorMessage(code) {
    return CONTROL_PASSWORD_ERRORS[String(code)] || 'Unknown control password error';
}

// Helper to check if endpoint is not supported
function isEndpointNotSupported(code) {
    return String(code) === ENDPOINT_NOT_SUPPORTED_CODE;
}

// Build EMQ broker request
// Endpoint: /app/emqAuth/getEmqBrokerIp
// Sample Response (decrypted respondData):
// { "emqBorker": "emq-eu.bydcloud.com:8883" }
function buildEmqBrokerRequest(session, countryCode, language, deviceConfig) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build MQTT client ID
function buildMqttClientId(imeiMd5) {
    return `oversea_${String(imeiMd5).toUpperCase()}`;
}

// Build MQTT password
// Format: <timestamp_seconds><md5(signToken + clientId + userId + timestamp_seconds)>
function buildMqttPassword(session, clientId, tsSeconds) {
    const base = `${session.signToken}${clientId}${session.userId}${tsSeconds}`;
    const hash = md5Hex(base);
    return `${tsSeconds}${hash}`;
}

// Decrypt MQTT message payload
// MQTT messages use AES-128-CBC with MD5(encryToken) as key
function decryptMqttPayload(encryptedHex, encryToken) {
    const contentKey = md5Hex(encryToken);
    return aesDecryptUtf8(encryptedHex, contentKey);
}

module.exports = {
    BASE_URL,
    USER_AGENT,
    SESSION_EXPIRED_CODES,
    DEFAULT_DEVICE_CONFIG,
    pwdLoginKey,
    encodeEnvelope,
    decodeEnvelope,
    decryptResponseData,
    buildLoginRequest,
    buildVehicleListRequest,
    buildVehicleRealtimeRequest,
    buildGpsInfoRequest,
    buildRemoteControlRequest,
    buildEnergyConsumptionRequest,
    buildHvacStatusRequest,
    buildChargingStatusRequest,
    buildEmqBrokerRequest,
    buildMqttClientId,
    buildMqttPassword,
    decryptMqttPayload,
    isRealtimeDataReady,
    isGpsDataReady,
    isRemoteControlReady,
    isSessionExpired,
    isRateLimited,
    isControlPasswordError,
    getControlPasswordErrorMessage,
    isEndpointNotSupported,
    RATE_LIMIT_CODE,
    CONTROL_PASSWORD_ERRORS,
};
