'use strict';

const crypto = require('crypto');
const bangcle = require('./bangcle');

const BASE_URL = 'https://dilinkappoversea-eu.byd.auto';
const USER_AGENT = 'okhttp/4.12.0';
const TRANSPORT_KEY = '9F29BE3E6254AF2C354F265B17C0CDD3';

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

    const encryData = aesEncryptHex(JSON.stringify(inner), TRANSPORT_KEY);

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
/**
 *
 */
function buildRemoteControlRequest(
    session,
    countryCode,
    language,
    deviceConfig,
    vin,
    instructionCode,
    requestSerial = null,
) {
    const inner = {
        deviceType: deviceConfig.deviceType,
        imeiMD5: deviceConfig.imeiMd5,
        instructionCode,
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

module.exports = {
    BASE_URL,
    USER_AGENT,
    TRANSPORT_KEY,
    DEFAULT_DEVICE_CONFIG,
    encodeEnvelope,
    decodeEnvelope,
    decryptResponseData,
    buildLoginRequest,
    buildVehicleListRequest,
    buildVehicleRealtimeRequest,
    buildGpsInfoRequest,
    buildRemoteControlRequest,
    isRealtimeDataReady,
    isGpsDataReady,
    isRemoteControlReady,
};
