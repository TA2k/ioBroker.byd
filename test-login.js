'use strict';

const axios = require('axios').default;
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const bydapi = require('./lib/bydapi');

// Configuration - fill in your credentials
const USERNAME = 'tombox2020@gmail.com';
const PASSWORD = 'Fucked678';
const COUNTRY_CODE = 'DE';
const LANGUAGE = 'en';

const config = {
    username: USERNAME,
    password: PASSWORD,
    countryCode: COUNTRY_CODE,
    language: LANGUAGE,
};

const deviceConfig = bydapi.DEFAULT_DEVICE_CONFIG;

// Setup axios with cookie jar (exact copy from main.js)
const jar = new CookieJar();
const requestClient = wrapper(
    axios.create({
        withCredentials: true,
        timeout: 3 * 60 * 1000,
        jar,
    }),
);

// Login function (exact copy from main.js)
async function login() {
    const { outer } = bydapi.buildLoginRequest(
        config.username,
        config.password,
        config.countryCode,
        config.language,
        deviceConfig,
    );

    const envelope = bydapi.encodeEnvelope(outer);

    console.log('Sending login request...');
    console.log('URL:', `${bydapi.BASE_URL}/app/account/login`);

    let session = null;

    await requestClient({
        method: 'post',
        url: `${bydapi.BASE_URL}/app/account/login`,
        headers: {
            'User-Agent': bydapi.USER_AGENT,
            'Content-Type': 'application/json; charset=UTF-8',
        },
        data: { request: envelope },
    })
        .then(async res => {
            console.log('Login response status:', res.status);
            console.log('Login response data type:', typeof res.data);
            console.log('Login response data:', JSON.stringify(res.data).substring(0, 500));

            const decoded = bydapi.decodeEnvelope(res.data);
            console.log('Decoded login:', JSON.stringify(decoded, null, 2));

            if (decoded.code !== '0') {
                console.error(`Login failed: code=${decoded.code} message=${decoded.message || ''}`);
                return;
            }

            const data = decoded.data || decoded;
            session = {
                userId: data.userId,
                signToken: data.signToken,
                encryToken: data.encryToken,
            };

            console.log('Login successful!');
            console.log('Session:', JSON.stringify(session, null, 2));
        })
        .catch(error => {
            console.error('Login error:', error.message);
            error.response && console.error('Response data:', JSON.stringify(error.response.data));
        });

    return session;
}

// Get vehicle list (exact copy from main.js)
async function getVehicleList(session) {
    if (!session) {
        console.error('No session - cannot get vehicle list');
        return null;
    }

    const { outer, contentKey } = bydapi.buildVehicleListRequest(
        session,
        config.countryCode,
        config.language,
        deviceConfig,
    );

    const envelope = bydapi.encodeEnvelope(outer);

    console.log('\nGetting vehicle list...');
    console.log('URL:', `${bydapi.BASE_URL}/app/account/getAllListByUserId`);

    let vehicles = null;

    await requestClient({
        method: 'post',
        url: `${bydapi.BASE_URL}/app/account/getAllListByUserId`,
        headers: {
            'User-Agent': bydapi.USER_AGENT,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        data: envelope,
    })
        .then(async res => {
            console.log('Vehicle list response status:', res.status);

            const decoded = bydapi.decodeEnvelope(res.data);

            if (decoded.code !== '200') {
                console.error('Vehicle list failed:', decoded.msg || decoded.code);
                return;
            }

            const data = bydapi.decryptResponseData(decoded.respondData, contentKey);
            console.log('Vehicle list:', JSON.stringify(data, null, 2));

            vehicles = data.allCarList || [];
            console.log(`Found ${vehicles.length} vehicle(s)`);
        })
        .catch(error => {
            console.error('Vehicle list error:', error.message);
            error.response && console.error('Response data:', JSON.stringify(error.response.data));
        });

    return vehicles;
}

// Main test
async function main() {
    console.log('=== BYD API Login Test ===\n');

    if (!config.username || !config.password) {
        console.error('Please set USERNAME and PASSWORD in test-login.js');
        process.exit(1);
    }

    console.log('Config:', {
        username: config.username,
        password: '***',
        countryCode: config.countryCode,
        language: config.language,
    });
    console.log('');

    const session = await login();

    if (session) {
        await getVehicleList(session);
    }

    console.log('\n=== Test Complete ===');
}

main().catch(console.error);
