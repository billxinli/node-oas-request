const jwt = require('jsonwebtoken')
const parseSecurity = require('../lib/security')
const { test } = require('tap')

test('simple case', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    BearerAuth: {
      type: 'http',
      scheme: 'bearer'
    },
    ApiKeyAuthHeader: {
      type: 'apiKey',
      in: 'header',
      name: 'header_key'
    },
    ApiKeyAuthQuery: {
      type: 'apiKey',
      in: 'query',
      name: 'query_key'
    },
    BearerAuthJWT: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT'
    }
  }

  const mockSecret = '__secret__'
  const result =
    await parseSecurity(mockOasSecuritySchemes,
      {
        BearerAuth: [],
        ApiKeyAuthHeader: [],
        ApiKeyAuthQuery: []
      },
      {
        BearerAuth: mockSecret,
        ApiKeyAuthHeader: mockSecret,
        ApiKeyAuthQuery: mockSecret
      })

  assert.deepEqual(result, {
    headers: {
      header_key: [mockSecret],
      authorization: [`Bearer ${mockSecret}`]
    },
    queries: {
      query_key: [mockSecret]
    }
  })
})

test('api key with multiple values case', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    ApiKeyAuthHeader: {
      type: 'apiKey',
      in: 'header',
      name: 'header_key'
    },
    ApiKeyAuthQuery: {
      type: 'apiKey',
      in: 'query',
      name: 'query_key'
    },
    ApiKeyAuthHeaderAnother: {
      type: 'apiKey',
      in: 'header',
      name: 'header_key'
    },
    ApiKeyAuthQueryAnother: {
      type: 'apiKey',
      in: 'query',
      name: 'query_key'
    }
  }

  const mockSecret = '__secret__'
  const result =
    await parseSecurity(mockOasSecuritySchemes,
      {
        ApiKeyAuthHeader: [],
        ApiKeyAuthQuery: [],
        ApiKeyAuthHeaderAnother: [],
        ApiKeyAuthQueryAnother: []
      },
      {
        ApiKeyAuthHeader: mockSecret,
        ApiKeyAuthQuery: mockSecret,
        ApiKeyAuthHeaderAnother: mockSecret,
        ApiKeyAuthQueryAnother: mockSecret
      })

  assert.deepEqual(result, {
    headers: {
      header_key: [mockSecret, mockSecret]
    },
    queries: {
      query_key: [mockSecret, mockSecret]
    }
  })
})

test('bearer with multiple values case', async (assert) => {
  assert.plan(2)

  const mockOasSecuritySchemes = {
    BearerAuth: {
      type: 'http',
      scheme: 'bearer'
    },
    BearerAuthJWT: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT'
    }
  }

  const mockSecret = '__secret__'
  const result =
    await parseSecurity(mockOasSecuritySchemes,
      {
        BearerAuth: [],
        BearerAuthJWT: []
      },
      {
        BearerAuth: mockSecret,
        BearerAuthJWT: {
          secret: mockSecret,
          exp: '5m',
          payload: {}
        }
      })

  assert.equal(result.headers.authorization[0], `Bearer ${mockSecret}`)
  assert.ok(result.headers.authorization[1] !== `Bearer ${mockSecret}`)
})

test('http basic is not supported', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    BasicAuth: {
      type: 'http',
      scheme: 'basic'
    }
  }

  const mockSecret = '__secret__'

  try {
    await parseSecurity(mockOasSecuritySchemes,
      {
        BasicAuth: []
      },
      {
        BasicAuth: mockSecret
      })
  } catch (err) {
    assert.equal(err.message, 'basic scheme type not implemented.')
  }
})

test('oauth2 is not supported', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    OauthAuth: {
      type: 'oauth2'
    }
  }

  const mockSecret = '__secret__'

  try {
    await parseSecurity(mockOasSecuritySchemes,
      {
        OauthAuth: []
      },
      {
        OauthAuth: mockSecret
      })
  } catch (err) {
    assert.equal(err.message, 'oauth2 type not implemented.')
  }
})

test('openIdConnect is not supported', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    OpenIdConnectAuth: {
      type: 'openIdConnect'
    }
  }

  const mockSecret = '__secret__'

  try {
    await parseSecurity(mockOasSecuritySchemes,
      {
        OpenIdConnectAuth: []
      },
      {
        OpenIdConnectAuth: mockSecret
      })
  } catch (err) {
    assert.equal(err.message, 'openIdConnect type not implemented.')
  }
})

test('apiKey in cookie is not supported', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    CookieAuth: {
      type: 'apiKey',
      in: 'cookie'
    }
  }

  const mockSecret = '__secret__'

  try {
    await parseSecurity(mockOasSecuritySchemes,
      {
        CookieAuth: []
      },
      {
        CookieAuth: mockSecret
      })
  } catch (err) {
    assert.equal(err.message, 'cookie in type not implemented.')
  }
})

test('jwt with invalid options', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    BearerAuthJWT: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT'
    }
  }

  const mockSecret = '__secret__'

  try {
    await parseSecurity(mockOasSecuritySchemes,
      {
        BearerAuthJWT: []
      },
      {
        BearerAuthJWT: {
          secret: mockSecret,
          exp: 'some invalid value',
          payload: {}
        }
      })
  } catch (err) {
    assert.equal(err.message, '"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60')
  }
})

test('jwt with exp time', async (assert) => {
  assert.plan(2)

  const mockOasSecuritySchemes = {
    BearerAuthJWT: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT'
    }
  }

  const mockSecret = '__secret__'
  const now = Math.floor(Date.now() / 1000)

  const result =
    await parseSecurity(mockOasSecuritySchemes,
      {
        BearerAuthJWT: []
      },
      {
        BearerAuthJWT: {
          secret: mockSecret,
          exp: '5m',
          payload: {}
        }
      })

  const jwtToken = result.headers.authorization[0].split('Bearer ')[1]

  const decoded = jwt.decode(jwtToken, { complete: true })

  assert.ok(now + (5 * 60) + 1 >= decoded.payload.exp)
  assert.ok(now + (5 * 60) - 1 <= decoded.payload.exp)
})

test('jwt without exp time', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    BearerAuthJWT: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT'
    }
  }

  const mockSecret = '__secret__'

  const result =
    await parseSecurity(mockOasSecuritySchemes,
      {
        BearerAuthJWT: []
      },
      {
        BearerAuthJWT: {
          secret: mockSecret,
          payload: {}
        }
      })

  const jwtToken = result.headers.authorization[0].split('Bearer ')[1]

  const decoded = jwt.decode(jwtToken, { complete: true })

  assert.equal(decoded.payload.exp, undefined)
})

test('jwt without options', async (assert) => {
  assert.plan(1)

  const mockOasSecuritySchemes = {
    BearerAuthJWT: {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT'
    }
  }

  const mockSecret = '__secret__'

  const result =
    await parseSecurity(mockOasSecuritySchemes,
      {
        BearerAuthJWT: []
      },
      {
        BearerAuthJWT: {
          secret: mockSecret,
          payload: {}
        }
      })

  const jwtToken = result.headers.authorization[0].split('Bearer ')[1]

  const decoded = jwt.decode(jwtToken, { complete: true })

  assert.equal(decoded.payload.exp, undefined)
})
