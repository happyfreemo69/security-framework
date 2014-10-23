var chai = require("chai");
var chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);

var should = require('chai').should(),
        expect = require('chai').expect,
        assert = require('chai').assert;

var Promise = require('bluebird');
var _ = require('lodash');

var express = require('express');
var request = require('supertest')

describe('Sample', function() {
    it('should good', function() {

        security.isAllowed(role);
        security.setUser(object, roles);
        security.addRoles(roles);

        security.secureRoute(route, role);


        return true;
    });

})

