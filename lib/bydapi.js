'use strict';

const crypto = require('crypto');
const bangcle = require('./bangcle');

const BASE_URL = 'https://dilinkappoversea-eu.byd.auto';
const USER_AGENT = 'okhttp/4.12.0';
const APP_NAME = 'iobroker.byd';

// Session expired error codes - trigger re-authentication
const SESSION_EXPIRED_CODES = new Set(['1002', '1005', '1010']);

// Rate limit error code - command in progress or too many requests
const RATE_LIMIT_CODE = '6024';

// Service busy - recoverable transient failure (dominant on EU cars); retain last data and back off
const SERVICE_BUSY_CODE = '1008';

// Vehicle unreachable - T-Box offline/asleep; retain last-known data and skip
const VEHICLE_UNREACHABLE_CODE = '6002';

// Guest-account userType (car shared via "Family and friends"). Since ~2025-11 the
// cloud refuses a car-reaching request from a guest that does not send a signed
// outer userType:"1" (code 1001), and from an owner that does send it (code 8003).
const USER_TYPE_GUEST = '1';
const GUEST_NOT_DECLARED_CODE = '1001';
const NOT_A_GUEST_CODE = '8003';

// Control password error codes
const CONTROL_PASSWORD_ERRORS = {
    '5005': 'Wrong control PIN - the PIN in ioBroker does not match the PIN in the BYD app',
    '5006': 'Control PIN locked for today (too many wrong attempts)',
    '5011': 'No control PIN set in BYD app - go to BYD app > Settings > Security > Set Remote Control Password',
};

// Error code for "no PIN set in app" - special handling needed
const NO_CONTROL_PIN_SET_CODE = '5011';

// Remote control service error
const REMOTE_CONTROL_SERVICE_ERROR_CODE = '1009';

// Endpoint not supported
const ENDPOINT_NOT_SUPPORTED_CODE = '1001';

const DEFAULT_DEVICE_CONFIG = Object.freeze({
    ostype: 'and',
    imei: 'BANGCLE01234',
    mac: '00:00:00:00:00:00',
    model: 'POCO F1',
    sdk: '35',
    mod: 'Xiaomi',
    imeiMd5: '00000000000000000000000000000000',
    mobileBrand: 'XIAOMI',
    mobileModel: 'POCO F1',
    deviceType: '0',
    networkType: 'wifi',
    osType: '15',
    osVersion: '35',
    deviceName: 'XIAOMIPOCO F1',
    appVersion: '3.6.0',
    appInnerVersion: '360',
    timeZone: 'Europe/Amsterdam',
    softType: '0',
    tboxVersion: '3',
    isAuto: '1',
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
function buildLoginRequest(username, password, countryCode, language, deviceConfig, identifierType = '0') {
    const nowMs = Date.now();
    const random = randomHex16();
    const reqTimestamp = String(nowMs);
    const serviceTime = String(Date.now());

    const inner = {
        agreeStatus: '0',
        agreementType: '[1,2]',
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
        appName: APP_NAME,
        countryCode,
        functionType: 'pwdLogin',
        identifier: username,
        identifierType,
        language,
        reqTimestamp,
    };

    const sign = sha1Mixed(buildSignString(signFields, md5Hex(password)));

    const outer = /** @type {Record<string, any>} */ ({
        appName: APP_NAME,
        countryCode,
        encryData,
        functionType: 'pwdLogin',
        identifier: username,
        identifierType,
        imeiMD5: deviceConfig.imeiMd5,
        isAuto: deviceConfig.isAuto,
        language,
        reqTimestamp,
        sign,
        signKey: password,
        ...commonOuterFields(deviceConfig),
        serviceTime,
    });
    outer.checkcode = computeCheckcode(outer);

    return { outer };
}

// Build token-based request envelope.
// `userType` is the signed guest marker ("1") for a car shared via "Family and
// friends"; omit (null) for an owner account. The cloud refuses a guest that does
// not declare it (code 1001) and an owner that does (code 8003), so it must be
// both signed and present in the outer.
function buildTokenEnvelope(session, countryCode, language, deviceConfig, inner, userType = null) {
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
    if (userType) {
        signFields.userType = userType;
    }
    const sign = sha1Mixed(buildSignString(signFields, signKey));

    const outer = /** @type {Record<string, any>} */ ({
        countryCode,
        encryData,
        identifier: session.userId,
        imeiMD5: deviceConfig.imeiMd5,
        language,
        reqTimestamp,
        sign,
        ...commonOuterFields(deviceConfig),
        serviceTime: String(Date.now()),
    });
    if (userType) {
        outer.userType = userType;
    }
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
function buildVehicleRealtimeRequest(session, countryCode, language, deviceConfig, vin, requestSerial, userType) {
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
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner, userType);
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
function buildGpsInfoRequest(session, countryCode, language, deviceConfig, vin, requestSerial, userType) {
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
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner, userType);
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
    commandPwd,
    requestSerial,
    userType,
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
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner, userType);
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
function buildHvacStatusRequest(session, countryCode, language, deviceConfig, vin, userType) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner, userType);
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

// Fields whose negative value is a "no data" sentinel (normalise to removed)
const NEGATIVE_SENTINEL_FIELDS = [
    'oilPercent',
    'oilEndurance',
    'enduranceMileage',
    'enduranceMileageV2',
    'elecPercent',
    'ect',
    'ectValue',
    'absWarning',
    'svs',
    'srs',
    'eps',
    'esp',
    'tirepressureSystem',
    'oilPressureSystem',
    'rapidTireLeak',
    'leftFrontTireStatus',
    'rightFrontTireStatus',
    'leftRearTireStatus',
    'rightRearTireStatus',
];

// Temperature fields using -127/-129 as "no sensor / no data" sentinel
const TEMP_SENTINEL_FIELDS = [
    'tempInCar',
    'tempOutCar',
    'leftFrontTireTemperature',
    'rightFrontTireTemperature',
    'leftRearTireTemperature',
    'rightRearTireTemperature',
];

// Consumption/energy string fields that use "--"/empty as "no data"
const CONSUMPTION_STRING_FIELDS = [
    'totalEnergy',
    'totalConsumption',
    'totalConsumptionEn',
    'energyConsumption',
    'nearestEnergyConsumption',
    'recent50kmEnergy',
];

/**
 * Remove "no data" sentinel values from a realtime/HVAC payload in place so that
 * json2iob does not create misleading states and the previous good value survives.
 * Negative sentinels, -127/-129 temperature sentinels, rate <= -9 and "--" strings
 * are deleted from the object.
 *
 * @param {object} data - Decrypted realtime or HVAC payload (mutated in place)
 * @returns {object} The same object, cleaned
 */
function sanitizeRealtime(data) {
    if (!data || typeof data !== 'object') {
        return data;
    }
    for (const field of NEGATIVE_SENTINEL_FIELDS) {
        if (data[field] !== undefined && data[field] !== null && data[field] !== '' && Number(data[field]) < 0) {
            delete data[field];
        }
    }
    for (const field of TEMP_SENTINEL_FIELDS) {
        if (data[field] !== undefined && data[field] !== null && data[field] !== '' && Number(data[field]) <= -127) {
            delete data[field];
        }
    }
    if (data.rate !== undefined && data.rate !== null && data.rate !== '' && Number(data.rate) <= -9) {
        delete data.rate;
    }
    for (const field of CONSUMPTION_STRING_FIELDS) {
        const value = data[field];
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (trimmed === '' || trimmed === '--') {
                delete data[field];
            }
        }
    }
    return data;
}

// Keys whose value must never appear in a debug log (tokens, credentials, encrypted blobs)
const REDACT_KEYS = new Set([
    'password',
    'signToken',
    'encryToken',
    'accessToken',
    'token',
    'encryData',
    'respondData',
    'sign',
    'signKey',
    'commandPwd',
    'checkcode',
]);

const REDACT_MAX_STRING = 120;

/**
 * Return a redacted deep copy of a decoded payload for safe DEBUG logging.
 * Sensitive keys are masked and over-long strings are truncated.
 *
 * @param {*} value - Decoded/decrypted payload
 * @returns {*} Redacted copy safe to log
 */
function redactForLog(value) {
    if (Array.isArray(value)) {
        return value.map(redactForLog);
    }
    if (value && typeof value === 'object') {
        const out = {};
        for (const [key, val] of Object.entries(value)) {
            if (REDACT_KEYS.has(key)) {
                out[key] = '***';
            } else {
                out[key] = redactForLog(val);
            }
        }
        return out;
    }
    if (typeof value === 'string' && value.length > REDACT_MAX_STRING) {
        return `${value.slice(0, REDACT_MAX_STRING)}...(${value.length})`;
    }
    return value;
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
    // res field: 1 = keep polling, >= 2 = terminal (2 = success)
    if (data.res !== undefined && Number(data.res) >= 2) {
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

// Helper to check if error code indicates a recoverable service-busy condition
function isServiceBusy(code) {
    return String(code) === SERVICE_BUSY_CODE;
}

// Helper to check if error code indicates the vehicle is unreachable (T-Box offline/asleep)
function isVehicleUnreachable(code) {
    return String(code) === VEHICLE_UNREACHABLE_CODE;
}

// Error code returned when the current userType guess was wrong for this VIN.
// A guest that did not declare itself gets 1001; an owner that wrongly declared
// itself a guest gets 8003. Used to self-correct the per-VIN guest flag.
function isWrongUserType(code, assumedGuest) {
    return String(code) === (assumedGuest ? NOT_A_GUEST_CODE : GUEST_NOT_DECLARED_CODE);
}

// Helper to check if error code indicates control password error
function isControlPasswordError(code) {
    return String(code) in CONTROL_PASSWORD_ERRORS;
}

// Get control password error message
function getControlPasswordErrorMessage(code) {
    return CONTROL_PASSWORD_ERRORS[String(code)] || 'Unknown control password error';
}

// Check if error indicates no PIN is set in BYD app
function isNoPinSetError(code) {
    return String(code) === NO_CONTROL_PIN_SET_CODE;
}

// Helper to check if endpoint is not supported
function isEndpointNotSupported(code) {
    return String(code) === ENDPOINT_NOT_SUPPORTED_CODE;
}

// Helper to check if remote control service error
function isRemoteControlServiceError(code) {
    return String(code) === REMOTE_CONTROL_SERVICE_ERROR_CODE;
}

// Build verify control password request
// Endpoint: /vehicle/vehicleswitch/verifyControlPassword
// Sample Response (decrypted respondData):
// { "ok": true } or error code 5005/5006
function buildVerifyControlPasswordRequest(session, countryCode, language, deviceConfig, vin, controlPin) {
    const inner = {
        commandPwd: md5Hex(controlPin),
        deviceType: deviceConfig.deviceType,
        functionType: 'remoteControl',
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build smart charging toggle request
// Endpoint: /control/smartCharge/changeChargeStatue
// Sample Response: { "code": "0" } on success
function buildSmartChargingToggleRequest(session, countryCode, language, deviceConfig, vin, enable) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        smartChargeSwitch: enable ? '1' : '0',
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build smart charging change-result poll request
// Endpoint: /control/smartCharge/changeResult
// Poll response res: 1 = pending, 2 = success (terminal), other = failure
function buildSmartChargeResultRequest(session, countryCode, language, deviceConfig, vin, requestSerial) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        requestSerial,
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build smart charging schedule request
// Endpoint: /control/smartCharge/saveOrUpdate
// Sample Response: { "code": "0" } on success
function buildSmartChargingScheduleRequest(
    session,
    countryCode,
    language,
    deviceConfig,
    vin,
    targetSoc,
    startHour,
    startMinute,
    endHour,
    endMinute,
) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        endHour: String(endHour),
        endMinute: String(endMinute),
        imeiMD5: deviceConfig.imeiMd5,
        networkType: deviceConfig.networkType,
        random: randomHex16(),
        smartChargeSwitch: '1',
        startHour: String(startHour),
        startMinute: String(startMinute),
        targetSoc: String(targetSoc),
        timeStamp: String(Date.now()),
        version: deviceConfig.appInnerVersion,
        vin,
    };
    return buildTokenEnvelope(session, countryCode, language, deviceConfig, inner);
}

// Build vehicle rename request
// Endpoint: /control/vehicle/modifyAutoAlias
// Sample Response: { "code": "0" } on success
function buildRenameVehicleRequest(session, countryCode, language, deviceConfig, vin, newName) {
    const inner = {
        autoAlias: newName,
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

// Build battery heat control params
// Used with BATTERYHEAT commandType
function buildBatteryHeatParams(enable) {
    return {
        batteryHeat: enable ? 1 : 0,
    };
}

// Build detailed seat climate params
// Used with VENTILATIONHEATING commandType
// Levels: 0=off, 1=low, 2=medium, 3=high
function buildSeatClimateParams(options = {}) {
    return {
        chairType: '5',
        copilotHeat: options.copilotHeat ?? 0,
        copilotVentilation: options.copilotVentilation ?? 0,
        lrSeatHeatState: options.lrSeatHeat ?? 0,
        lrSeatVentilationState: options.lrSeatVentilation ?? 0,
        lrThirdHeatState: 0,
        lrThirdVentilationState: 0,
        mainHeat: options.mainHeat ?? 0,
        mainVentilation: options.mainVentilation ?? 0,
        remoteMode: options.mainHeat || options.copilotHeat || options.steeringWheelHeat ? 1 : 0,
        rrSeatHeatState: options.rrSeatHeat ?? 0,
        rrSeatVentilationState: options.rrSeatVentilation ?? 0,
        rrThirdHeatState: 0,
        rrThirdVentilationState: 0,
        steeringWheelHeatState: options.steeringWheelHeat ?? 0,
    };
}

// Build detailed climate control params
// Used with OPENAIR/CLOSEAIR commandType
// Temperature scale: 1-17 maps to 15-31°C (each step = 1°C)
function buildClimateParams(options = {}) {
    const tempToScale = tempC => Math.max(1, Math.min(17, Math.round(tempC - 14)));
    return {
        acSwitch: options.acSwitch ?? 1,
        airAccuracy: options.airAccuracy ?? 1,
        airConditioningMode: options.airConditioningMode ?? 1,
        airSet: options.airSet ?? null,
        copilotSettingTemp: options.copilotTempC ? tempToScale(options.copilotTempC) : options.copilotTemp ?? 7,
        cycleMode: options.cycleMode ?? 2,
        mainSettingTemp: options.tempC ? tempToScale(options.tempC) : options.temp ?? 7,
        remoteMode: options.remoteMode ?? 4,
        timeSpan: options.timeSpan ?? 1, // 1=10min, 2=15min, 3=20min, 4=25min, 5=30min
        windLevel: options.windLevel ?? null,
        windPosition: options.windPosition ?? null,
    };
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
    md5Hex,
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
    buildVerifyControlPasswordRequest,
    buildSmartChargingToggleRequest,
    buildSmartChargeResultRequest,
    buildSmartChargingScheduleRequest,
    buildRenameVehicleRequest,
    buildBatteryHeatParams,
    buildSeatClimateParams,
    buildClimateParams,
    buildEmqBrokerRequest,
    buildMqttClientId,
    buildMqttPassword,
    decryptMqttPayload,
    isRealtimeDataReady,
    isGpsDataReady,
    isRemoteControlReady,
    sanitizeRealtime,
    redactForLog,
    isSessionExpired,
    isRateLimited,
    isServiceBusy,
    isVehicleUnreachable,
    isWrongUserType,
    isControlPasswordError,
    getControlPasswordErrorMessage,
    isEndpointNotSupported,
    isRemoteControlServiceError,
    isNoPinSetError,
    RATE_LIMIT_CODE,
    SERVICE_BUSY_CODE,
    VEHICLE_UNREACHABLE_CODE,
    USER_TYPE_GUEST,
    GUEST_NOT_DECLARED_CODE,
    NOT_A_GUEST_CODE,
    CONTROL_PASSWORD_ERRORS,
    REMOTE_CONTROL_SERVICE_ERROR_CODE,
    NO_CONTROL_PIN_SET_CODE,
};
