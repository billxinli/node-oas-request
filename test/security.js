const jwt = require('jsonwebtoken')
const { test } = require('tap')
const sinon = require('sinon')

// create stub
const http = sinon.stub()

// delete require cache
delete require.cache[require.resolve('../lib/http/')]

// override required module
require.cache[require.resolve('../lib/http/')] = { exports: http }

const globalSecuritySpec = require('./fixtures/global-security.json')
const methodSecuritySpec = require('./fixtures/method-security.json')
const missingSecuritySpec = require('./fixtures/missing-security.json')
const emptySecuritySpec = require('./fixtures/empty-security.json')

const client = require('..')

test('per method overrides security values', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/method-specific-security?query_key=per-method-override-query',
      headers: {
        header_key: 'per-method-override-header'
      },
      body: undefined
    })
  })

  const API = client(globalSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      ApiKeyAuthHeader: 'secret',
      ApiKeyAuthQuery: 'secret'
    }
  })

  await api.testMethodSpecific({
    query: {
      query_key: 'per-method-override-query'
    },
    headers: {
      header_key: 'per-method-override-header'
    }
  })
})

test('global security is applied', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/global-security',
      headers: {
        header_key: [
          'secret'
        ]
      },
      body: undefined
    })
  })

  const API = client(globalSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      ApiKeyAuthHeader: 'secret',
      ApiKeyAuthQuery: 'secret'
    }
  })

  await api.testGlobal()
})

test('global security with method security is applied', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/method-specific-security?query_key=secret',
      headers: {
        header_key: [
          'secret'
        ]
      },
      body: undefined
    })
  })

  const API = client(globalSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      ApiKeyAuthHeader: 'secret',
      ApiKeyAuthQuery: 'secret'
    }
  })

  await api.testMethodSpecific()
})

test('global security with method security override', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/method-specific-security?query_key=method-secret',
      headers: {
        header_key: [
          'method-secret'
        ]
      },
      body: undefined
    })
  })

  const API = client(globalSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      ApiKeyAuthHeader: 'secret',
      ApiKeyAuthQuery: 'secret'
    }
  })

  await api.testMethodSpecific({
    security: {
      ApiKeyAuthHeader: 'method-secret',
      ApiKeyAuthQuery: 'method-secret'
    }
  })
})

test('method security is applied', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/global-security',
      headers: {},
      body: undefined
    })
  })

  const API = client(methodSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      BearerAuthJWT: {
        secret: 'secret',
        payload: {}
      }
    }
  })

  await api.testGlobal()
})

test('method security with method security is applied', async (assert) => {
  assert.plan(2)

  http.callsFake(options => {
    assert.deepEqual(options.path, '/method-specific-security')
    const jwtToken = options.headers.authorization[0].split('Bearer ')[1]

    const decoded = jwt.verify(jwtToken, 'secret', { complete: true })

    assert.equal(decoded.payload.exp, undefined)
  })

  const API = client(methodSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      BearerAuthJWT: {
        secret: 'secret',
        payload: {}
      }
    }
  })

  await api.testMethodSpecific()
})

test('method security with method security override', async (assert) => {
  assert.plan(3)

  const now = Math.floor(Date.now() / 1000)

  http.callsFake(options => {
    assert.deepEqual(options.path, '/method-specific-security')
    const jwtToken = options.headers.authorization[0].split('Bearer ')[1]

    const decoded = jwt.verify(jwtToken, 'another-secret', { complete: true })

    assert.ok(now + (5 * 60) + 1 >= decoded.payload.exp)
    assert.ok(now + (5 * 60) - 1 <= decoded.payload.exp)
  })

  const API = client(methodSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      BearerAuthJWT: {
        secret: 'secret',
        payload: {}
      }
    }
  })

  await api.testMethodSpecific({
    security: {
      BearerAuthJWT: {
        secret: 'another-secret',
        exp: '5m',
        payload: {}
      }
    }
  })
})

test('missing security raise error', async (assert) => {
  assert.plan(1)

  const API = client(missingSecuritySpec)
  const api = new API('http://example.com', {
    security: {
      MissingSecurityMethod: 'secret'
    }
  })

  try {
    await api.testGlobal()
  } catch (err) {
    assert.equal(err.message, 'Security scheme MissingSecurityMethod not defined in spec.')
  }
})

test('empty security global method', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/global-security',
      headers: {},
      body: undefined
    })
  })

  const API = client(emptySecuritySpec)
  const api = new API('http://example.com')

  await api.testGlobal()
})

test('empty security per method', async (assert) => {
  assert.plan(1)

  http.callsFake(options => {
    assert.deepEqual(options, {
      protocol: 'http',
      port: '',
      host: 'example.com',
      method: 'get',
      path: '/method-specific-security',
      headers: {},
      body: undefined
    })
  })

  const API = client(emptySecuritySpec)
  const api = new API('http://example.com')

  await api.testMethodSpecific()
})
