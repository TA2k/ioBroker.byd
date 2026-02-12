'use strict';

/**
 * Generate a randomized but realistic Android device fingerprint.
 */

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const DEVICE_POOL_FILE = path.join(__dirname, 'device_pool.json');

let devicePool = null;

/**
 * Load the device pool from JSON file.
 * @returns {Array<Object>}
 */
function loadDevicePool() {
    if (!devicePool) {
        const data = fs.readFileSync(DEVICE_POOL_FILE, 'utf8');
        devicePool = JSON.parse(data);
    }
    return devicePool;
}

/**
 * Calculate the Luhn check digit for a partial IMEI (first 14 digits).
 * @param {string} partial - First 14 digits of IMEI
 * @returns {string} - Check digit (0-9)
 */
function luhnCheckDigit(partial) {
    const digits = partial.split('').map(Number);
    let total = 0;
    for (let i = 0; i < digits.length; i++) {
        let d = digits[i];
        if (i % 2 === 1) {
            d *= 2;
            if (d > 9) {
                d -= 9;
            }
        }
        total += d;
    }
    return String((10 - (total % 10)) % 10);
}

/**
 * Generate a valid 15-digit IMEI using a real TAC prefix.
 * The TAC prefix (first 8 digits) identifies the device manufacturer/model.
 * The remaining 6 digits are a random serial, plus a Luhn check digit.
 * @param {string} tacPrefix - 8-digit TAC prefix
 * @returns {string} - 15-digit IMEI
 */
function generateImei(tacPrefix) {
    let serial = '';
    for (let i = 0; i < 6; i++) {
        serial += Math.floor(Math.random() * 10).toString();
    }
    const partial = tacPrefix + serial;
    return partial + luhnCheckDigit(partial);
}

/**
 * Generate a random locally-administered unicast MAC address.
 * The second nibble is set to 2/6/A/E (locally administered, unicast).
 * Format: XX:XX:XX:XX:XX:XX
 * @returns {string}
 */
function generateMac() {
    let firstByte = Math.floor(Math.random() * 256);
    firstByte = (firstByte | 0x02) & 0xFE; // locally-administered, unicast
    const octets = [firstByte];
    for (let i = 0; i < 5; i++) {
        octets.push(Math.floor(Math.random() * 256));
    }
    return octets.map(b => b.toString(16).padStart(2, '0')).join(':');
}

/**
 * Generate a complete, randomized DeviceProfile object.
 * Picks a random device from the pool, generates a valid IMEI with the
 * device's TAC prefix, derives imei_md5, and generates a random MAC.
 * All values are realistic for an Android 12-15 phone.
 * @returns {Object} Device profile with all required fields
 */
function generateDeviceProfile() {
    const pool = loadDevicePool();
    const device = pool[Math.floor(Math.random() * pool.length)];

    // Pick a consistent sdk/os pair from the device's options
    const idx = Math.floor(Math.random() * device.sdk_options.length);
    const sdk = device.sdk_options[idx];
    const osType = device.os_options[idx];

    const imei = generateImei(device.tac_prefix);
    const imeiMd5 = crypto.createHash('md5').update(imei, 'utf8').digest('hex');
    const mac = generateMac();

    return {
        ostype: 'and',
        imei: imei,
        mac: mac,
        model: device.model,
        sdk: sdk,
        mod: device.mod,
        imeiMd5: imeiMd5,
        mobileBrand: device.mobile_brand,
        mobileModel: device.mobile_model,
        deviceType: '0',
        networkType: 'wifi',
        osType: osType,
        osVersion: sdk,
        // Computed fields for login
        deviceName: `${device.mobile_brand}${device.mobile_model}`,
        appVersion: '3.2.2',
        appInnerVersion: '322',
    };
}

module.exports = {
    generateDeviceProfile,
    generateImei,
    generateMac,
    luhnCheckDigit,
};
