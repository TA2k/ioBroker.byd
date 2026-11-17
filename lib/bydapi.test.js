'use strict';

const { expect } = require('chai');
const bydapi = require('./bydapi');

describe('bydapi: command params', () => {
    it('buildBatteryHeatParams uses the batteryHeat field (not batteryHeatSwitch)', () => {
        expect(bydapi.buildBatteryHeatParams(true)).to.deep.equal({ batteryHeat: 1 });
        expect(bydapi.buildBatteryHeatParams(false)).to.deep.equal({ batteryHeat: 0 });
    });
});

describe('bydapi: sanitizeRealtime', () => {
    it('removes negative sentinels and keeps good values', () => {
        const data = {
            oilPercent: '-1',
            oilEndurance: '-1',
            enduranceMileage: '-1',
            elecPercent: '75',
            leftFrontTirepressure: '250',
            eps: '-1',
        };
        bydapi.sanitizeRealtime(data);
        expect(data).to.not.have.property('oilPercent');
        expect(data).to.not.have.property('oilEndurance');
        expect(data).to.not.have.property('enduranceMileage');
        expect(data).to.not.have.property('eps');
        expect(data.elecPercent).to.equal('75');
        expect(data.leftFrontTirepressure).to.equal('250');
    });

    it('drops -127 / -129 temperature sentinels', () => {
        const data = { tempInCar: '-129', tempOutCar: '-127', leftFrontTireTemperature: '-127' };
        bydapi.sanitizeRealtime(data);
        expect(data).to.not.have.property('tempInCar');
        expect(data).to.not.have.property('tempOutCar');
        expect(data).to.not.have.property('leftFrontTireTemperature');
    });

    it('drops rate <= -9 and keeps a valid rate', () => {
        const bad = { rate: '-999' };
        bydapi.sanitizeRealtime(bad);
        expect(bad).to.not.have.property('rate');
        const good = { rate: '5' };
        bydapi.sanitizeRealtime(good);
        expect(good.rate).to.equal('5');
    });

    it('maps "--"/empty consumption strings to removed', () => {
        const data = { totalConsumption: '--', energyConsumption: '', recent50kmEnergy: '12.3' };
        bydapi.sanitizeRealtime(data);
        expect(data).to.not.have.property('totalConsumption');
        expect(data).to.not.have.property('energyConsumption');
        expect(data.recent50kmEnergy).to.equal('12.3');
    });
});

describe('bydapi: redactForLog', () => {
    it('masks sensitive keys and leaves others', () => {
        const out = bydapi.redactForLog({ signToken: 'secret', encryToken: 'x', foo: 'bar' });
        expect(out.signToken).to.equal('***');
        expect(out.encryToken).to.equal('***');
        expect(out.foo).to.equal('bar');
    });

    it('truncates over-long strings and recurses into arrays/objects', () => {
        const long = 'a'.repeat(300);
        const out = bydapi.redactForLog({ list: [{ respondData: 'abc', note: long }] });
        expect(out.list[0].respondData).to.equal('***');
        expect(out.list[0].note).to.include('...(300)');
    });
});

describe('bydapi: error-code helpers', () => {
    it('recognises service-busy (1008) and vehicle-unreachable (6002)', () => {
        expect(bydapi.isServiceBusy('1008')).to.equal(true);
        expect(bydapi.isServiceBusy('0')).to.equal(false);
        expect(bydapi.isVehicleUnreachable('6002')).to.equal(true);
        expect(bydapi.isVehicleUnreachable('0')).to.equal(false);
    });
});

describe('bydapi: isRemoteControlReady', () => {
    it('treats res >= 2 as terminal and res == 1 as pending', () => {
        expect(bydapi.isRemoteControlReady({ res: 2 })).to.equal(true);
        expect(bydapi.isRemoteControlReady({ res: '2' })).to.equal(true);
        expect(bydapi.isRemoteControlReady({ res: 1 })).to.equal(false);
    });

    it('still honours controlState', () => {
        expect(bydapi.isRemoteControlReady({ controlState: '1' })).to.equal(true);
        expect(bydapi.isRemoteControlReady({ controlState: '0' })).to.equal(false);
    });
});

describe('bydapi: buildLoginRequest', () => {
    const device = bydapi.DEFAULT_DEVICE_CONFIG;

    it('includes appName and the configured identifierType in the outer payload', () => {
        const { outer } = bydapi.buildLoginRequest('user@example.com', 'pw', 'DE', 'de', device, '1');
        expect(outer.appName).to.be.a('string').and.not.equal('');
        expect(outer.identifierType).to.equal('1');
        expect(outer.checkcode).to.be.a('string');
    });

    it('defaults identifierType to "0"', () => {
        const { outer } = bydapi.buildLoginRequest('user@example.com', 'pw', 'DE', 'de', device);
        expect(outer.identifierType).to.equal('0');
    });

    it('encrypts agreeStatus/agreementType into the inner payload', () => {
        const password = 'pw';
        const { outer } = bydapi.buildLoginRequest('user@example.com', password, 'DE', 'de', device);
        const inner = bydapi.decryptResponseData(outer.encryData, bydapi.pwdLoginKey(password));
        expect(inner.agreeStatus).to.equal('0');
        expect(inner.agreementType).to.equal('[1,2]');
    });
});

describe('bydapi: guest userType', () => {
    const device = bydapi.DEFAULT_DEVICE_CONFIG;
    const session = { userId: '123', signToken: 'sign-token', encryToken: 'encry-token' };

    it('adds userType to the outer only when provided (guest), omits it for an owner', () => {
        const guest = bydapi.buildVehicleRealtimeRequest(session, 'DE', 'de', device, 'VIN1', null, '1');
        expect(guest.outer.userType).to.equal('1');
        const owner = bydapi.buildVehicleRealtimeRequest(session, 'DE', 'de', device, 'VIN1', null, null);
        expect(owner.outer).to.not.have.property('userType');
    });

    it('isWrongUserType: 1001 flags an undeclared guest, 8003 flags a wrong owner-claim', () => {
        // Assumed owner (not guest) + 1001 => should switch to guest
        expect(bydapi.isWrongUserType('1001', false)).to.equal(true);
        expect(bydapi.isWrongUserType('8003', false)).to.equal(false);
        // Assumed guest + 8003 => should switch to owner
        expect(bydapi.isWrongUserType('8003', true)).to.equal(true);
        expect(bydapi.isWrongUserType('1001', true)).to.equal(false);
    });
});
