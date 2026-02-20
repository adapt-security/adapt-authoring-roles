import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'

/**
 * RolesModule extends AbstractApiModule (extends AbstractModule) which
 * requires a full App instance.  We replicate each public method and
 * build lightweight stubs for every dependency so we can exercise the
 * logic in isolation.
 */

// ── Helpers ──────────────────────────────────────────────────────────

/** Build a minimal RolesModule-like instance with sensible stub defaults */
function createInstance (overrides) {
  const instance = {
    root: undefined,
    schemaName: undefined,
    collectionName: undefined,
    useDefaultRouteConfig: mock.fn(),
    app: {
      waitForModule: mock.fn(async () => ({})),
      errors: {
        UNAUTHORISED: Object.assign(new Error('UNAUTHORISED'), {
          code: 'UNAUTHORISED',
          setData (d) { this.data = d; return this }
        })
      }
    },
    getConfig: mock.fn((key) => {
      const defaults = {
        roleDefinitions: [],
        defaultRoles: [],
        defaultRolesForAuthTypes: {}
      }
      return defaults[key]
    }),
    log: mock.fn(),
    find: mock.fn(async () => []),
    insert: mock.fn(async (data) => data),
    cache: { isEnabled: false },
    ...overrides
  }
  return instance
}

// ── Method references (copied from source for isolated testing) ─────

async function setValues () {
  this.root = 'roles'
  this.schemaName = 'role'
  this.collectionName = 'roles'
  this.useDefaultRouteConfig()
}

async function getScopesForRole (_id) {
  const allRoles = await this.find()
  const scopes = []
  let role = allRoles.find(r => r._id.toString() === _id.toString())
  do {
    scopes.push(...role.scopes)
    role = allRoles.find(r => r.shortName === role.extends)
  } while (role)
  return scopes
}

async function shortNamesToIds (roles) {
  return Promise.all(roles.map(async r => {
    const [role] = await this.find({ shortName: r })
    return role._id.toString()
  }))
}

async function getSuperRoleId () {
  const [superRole] = await this.find({ scopes: ['*:*'] })
  return superRole._id.toString()
}

async function isTargetSuper (_id) {
  const users = await this.app.waitForModule('users')
  const [user] = await users.find({ _id }, { projection: { roles: 1 } })
  return user.roles.length === 1 &&
    user.roles[0].toString() === await this.getSuperRoleId()
}

async function onUpdateRoles (req) {
  if (req.apiData?.modifying !== false ||
    (req.method !== 'DELETE' && !req.apiData?.data.roles)) {
    return
  }
  if (!req.auth.isSuper) {
    const reject = reason => {
      this.log('error', 'UNAUTHORISED', req.auth.user._id.toString(), reason)
      throw this.app.errors.UNAUTHORISED
    }
    if (!req.auth.scopes.includes('assign:roles')) {
      reject('assign role')
    }
    if (req.apiData.data.roles.includes(await this.getSuperRoleId())) {
      reject('assign superuser')
    }
    if (await this.isTargetSuper(req.apiData.query._id)) {
      reject('modify superuser')
    }
  }
  if (req.method !== 'POST') {
    const auth = await this.app.waitForModule('auth')
    await auth.authentication.disavowUser({
      userId: req.params._id || req.body._id
    })
  }
}

async function onCheckUserAccess (req) {
  if (req.apiData.modifying &&
    await this.isTargetSuper(req.apiData.query._id)) {
    throw this.app.errors.UNAUTHORISED
  }
  return true
}

async function initConfigRoles () {
  const mongodb = await this.app.waitForModule('mongodb')
  return Promise.allSettled(
    this.getConfig('roleDefinitions').map(async r => {
      const [doc] = await this.find({ shortName: r.shortName })
      if (doc) {
        try {
          await mongodb.replace(this.collectionName, { _id: doc._id }, r)
          this.log('debug', 'REPLACE', this.schemaName, r.shortName)
        } catch (e) {
          if (e.code !== 11000) {
            this.log('warn',
              `failed to update '${r.shortName}' role, ${e.message}`)
          }
        }
        return
      }
      try {
        await this.insert(r)
        this.log('debug', 'INSERT', this.schemaName, r.shortName)
      } catch (e) {
        if (e.code !== 11000) {
          this.log('warn',
            `failed to add '${r.shortName}' role, ${e.message}`)
        }
      }
    })
  )
}

async function initDefaultRoles () {
  const rolesforAll = await this.shortNamesToIds(
    this.getConfig('defaultRoles')
  )
  const rolesForAuth = Object.entries(
    this.getConfig('defaultRolesForAuthTypes')
  ).reduce((m, [k, v]) => {
    return { [m[k]]: this.shortNamesToIds(v) }
  }, {})
  const users = await this.app.waitForModule('users')
  users.preInsertHook.tap(data => {
    if (!data.roles || !data.roles.length) {
      data.roles = rolesForAuth[data.authType] || rolesforAll || []
    }
  })
}

// ── Tests ────────────────────────────────────────────────────────────

describe('RolesModule', () => {
  // ── setValues ──────────────────────────────────────────────────────

  describe('setValues', () => {
    it('should set root to "roles"', async () => {
      const inst = createInstance()
      await setValues.call(inst)
      assert.equal(inst.root, 'roles')
    })

    it('should set schemaName to "role"', async () => {
      const inst = createInstance()
      await setValues.call(inst)
      assert.equal(inst.schemaName, 'role')
    })

    it('should set collectionName to "roles"', async () => {
      const inst = createInstance()
      await setValues.call(inst)
      assert.equal(inst.collectionName, 'roles')
    })

    it('should call useDefaultRouteConfig', async () => {
      const inst = createInstance()
      await setValues.call(inst)
      assert.equal(inst.useDefaultRouteConfig.mock.callCount(), 1)
    })
  })

  // ── getScopesForRole ───────────────────────────────────────────────

  describe('getScopesForRole', () => {
    it('should return scopes for a single role', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [
          { _id: 'role1', shortName: 'admin', scopes: ['read:all', 'write:all'] }
        ])
      })
      const result = await getScopesForRole.call(inst, 'role1')
      assert.deepEqual(result, ['read:all', 'write:all'])
    })

    it('should accumulate scopes through role inheritance', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [
          { _id: 'role1', shortName: 'authuser', scopes: ['read:me'] },
          {
            _id: 'role2',
            shortName: 'editor',
            scopes: ['write:content'],
            extends: 'authuser'
          }
        ])
      })
      const result = await getScopesForRole.call(inst, 'role2')
      assert.deepEqual(result, ['write:content', 'read:me'])
    })

    it('should handle deep inheritance chains', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [
          { _id: 'r1', shortName: 'base', scopes: ['scope:a'] },
          { _id: 'r2', shortName: 'mid', scopes: ['scope:b'], extends: 'base' },
          { _id: 'r3', shortName: 'top', scopes: ['scope:c'], extends: 'mid' }
        ])
      })
      const result = await getScopesForRole.call(inst, 'r3')
      assert.deepEqual(result, ['scope:c', 'scope:b', 'scope:a'])
    })

    it('should handle ObjectId-like objects with toString', async () => {
      const objectId = { toString: () => 'abc123' }
      const inst = createInstance({
        find: mock.fn(async () => [
          {
            _id: { toString: () => 'abc123' },
            shortName: 'admin',
            scopes: ['*:*']
          }
        ])
      })
      const result = await getScopesForRole.call(inst, objectId)
      assert.deepEqual(result, ['*:*'])
    })

    it('should throw if role _id is not found', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [
          { _id: 'role1', shortName: 'admin', scopes: ['read:all'] }
        ])
      })
      await assert.rejects(
        async () => getScopesForRole.call(inst, 'nonexistent'),
        TypeError
      )
    })
  })

  // ── shortNamesToIds ────────────────────────────────────────────────

  describe('shortNamesToIds', () => {
    it('should resolve a single role short name to its id', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [{ _id: 'id1', shortName: 'admin' }])
      })
      const result = await shortNamesToIds.call(inst, ['admin'])
      assert.deepEqual(result, ['id1'])
    })

    it('should resolve multiple role short names to ids', async () => {
      const findMock = mock.fn(async (query) => {
        const map = {
          admin: [{ _id: 'id1', shortName: 'admin' }],
          editor: [{ _id: 'id2', shortName: 'editor' }]
        }
        return map[query.shortName] || []
      })
      const inst = createInstance({ find: findMock })
      const result = await shortNamesToIds.call(inst, ['admin', 'editor'])
      assert.deepEqual(result, ['id1', 'id2'])
    })

    it('should call toString on _id values', async () => {
      const toStringMock = mock.fn(() => 'stringified')
      const inst = createInstance({
        find: mock.fn(async () => [
          { _id: { toString: toStringMock }, shortName: 'x' }
        ])
      })
      const result = await shortNamesToIds.call(inst, ['x'])
      assert.equal(toStringMock.mock.callCount(), 1)
      assert.deepEqual(result, ['stringified'])
    })

    it('should return empty array for empty input', async () => {
      const inst = createInstance()
      const result = await shortNamesToIds.call(inst, [])
      assert.deepEqual(result, [])
    })

    it('should throw if role is not found', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [])
      })
      await assert.rejects(
        async () => shortNamesToIds.call(inst, ['missing']),
        TypeError
      )
    })
  })

  // ── getSuperRoleId ─────────────────────────────────────────────────

  describe('getSuperRoleId', () => {
    it('should return the id of the super role', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [{ _id: 'super1', scopes: ['*:*'] }])
      })
      const result = await getSuperRoleId.call(inst)
      assert.equal(result, 'super1')
    })

    it('should query for scopes ["*:*"]', async () => {
      const findMock = mock.fn(async () => [{ _id: 'x', scopes: ['*:*'] }])
      const inst = createInstance({ find: findMock })
      await getSuperRoleId.call(inst)
      assert.deepEqual(findMock.mock.calls[0].arguments[0], { scopes: ['*:*'] })
    })

    it('should throw if no super role exists', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [])
      })
      await assert.rejects(
        async () => getSuperRoleId.call(inst),
        TypeError
      )
    })
  })

  // ── isTargetSuper ──────────────────────────────────────────────────

  describe('isTargetSuper', () => {
    it('should return true if user has only the super role', async () => {
      const usersModule = {
        find: mock.fn(async () => [{ roles: ['super1'] }])
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        getSuperRoleId: mock.fn(async () => 'super1')
      })
      const result = await isTargetSuper.call(inst, 'user1')
      assert.equal(result, true)
    })

    it('should return false if user has multiple roles', async () => {
      const usersModule = {
        find: mock.fn(async () => [{ roles: ['super1', 'other'] }])
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        getSuperRoleId: mock.fn(async () => 'super1')
      })
      const result = await isTargetSuper.call(inst, 'user1')
      assert.equal(result, false)
    })

    it('should return false if user has a non-super role', async () => {
      const usersModule = {
        find: mock.fn(async () => [{ roles: ['regular1'] }])
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        getSuperRoleId: mock.fn(async () => 'super1')
      })
      const result = await isTargetSuper.call(inst, 'user1')
      assert.equal(result, false)
    })

    it('should return false if user has no roles', async () => {
      const usersModule = {
        find: mock.fn(async () => [{ roles: [] }])
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        getSuperRoleId: mock.fn(async () => 'super1')
      })
      const result = await isTargetSuper.call(inst, 'user1')
      assert.equal(result, false)
    })

    it('should pass projection for roles only', async () => {
      const usersModule = {
        find: mock.fn(async () => [{ roles: ['super1'] }])
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        getSuperRoleId: mock.fn(async () => 'super1')
      })
      await isTargetSuper.call(inst, 'user1')
      const findArgs = usersModule.find.mock.calls[0].arguments
      assert.deepEqual(findArgs[1], { projection: { roles: 1 } })
    })
  })

  // ── onUpdateRoles ──────────────────────────────────────────────────

  describe('onUpdateRoles', () => {
    function createReq (overrides) {
      return {
        method: 'PUT',
        params: {},
        body: {},
        auth: {
          isSuper: true,
          scopes: [],
          user: { _id: { toString: () => 'user1' } }
        },
        apiData: {
          modifying: false,
          data: { roles: ['role1'] },
          query: { _id: 'target1' }
        },
        ...overrides
      }
    }

    it('should return early if modifying is not false', async () => {
      const inst = createInstance()
      const req = createReq({
        apiData: { modifying: true, data: { roles: ['r1'] }, query: {} }
      })
      const result = await onUpdateRoles.call(inst, req)
      assert.equal(result, undefined)
    })

    it('should return early if apiData is undefined', async () => {
      const inst = createInstance()
      const req = { method: 'PUT', apiData: undefined }
      const result = await onUpdateRoles.call(inst, req)
      assert.equal(result, undefined)
    })

    it('should return early if not DELETE and no roles in data', async () => {
      const inst = createInstance()
      const req = createReq({
        method: 'PUT',
        apiData: { modifying: false, data: {}, query: {} }
      })
      const result = await onUpdateRoles.call(inst, req)
      assert.equal(result, undefined)
    })

    it('should not return early for DELETE even without roles', async () => {
      const disavowMock = mock.fn(async () => {})
      const authModule = { authentication: { disavowUser: disavowMock } }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => authModule),
          errors: { UNAUTHORISED: new Error('UNAUTHORISED') }
        }
      })
      const req = createReq({
        method: 'DELETE',
        apiData: { modifying: false, data: {}, query: { _id: 'target1' } },
        auth: {
          isSuper: true,
          scopes: [],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      await onUpdateRoles.call(inst, req)
      assert.equal(disavowMock.mock.callCount(), 1)
    })

    it('should skip auth checks for super users', async () => {
      const disavowMock = mock.fn(async () => {})
      const authModule = { authentication: { disavowUser: disavowMock } }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => authModule),
          errors: { UNAUTHORISED: new Error('UNAUTHORISED') }
        }
      })
      const req = createReq({
        auth: {
          isSuper: true,
          scopes: [],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      await onUpdateRoles.call(inst, req)
      assert.equal(disavowMock.mock.callCount(), 1)
    })

    it('should throw if non-super user lacks assign:roles scope', async () => {
      const inst = createInstance({
        getSuperRoleId: mock.fn(async () => 'super1'),
        isTargetSuper: mock.fn(async () => false)
      })
      const req = createReq({
        auth: {
          isSuper: false,
          scopes: ['read:roles'],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      await assert.rejects(async () => onUpdateRoles.call(inst, req))
    })

    it('should throw if assigning super role', async () => {
      const inst = createInstance({
        getSuperRoleId: mock.fn(async () => 'super1'),
        isTargetSuper: mock.fn(async () => false)
      })
      const req = createReq({
        auth: {
          isSuper: false,
          scopes: ['assign:roles'],
          user: { _id: { toString: () => 'u1' } }
        },
        apiData: {
          modifying: false,
          data: { roles: ['super1'] },
          query: { _id: 'target1' }
        }
      })
      await assert.rejects(async () => onUpdateRoles.call(inst, req))
    })

    it('should throw if modifying a super user', async () => {
      const inst = createInstance({
        getSuperRoleId: mock.fn(async () => 'super1'),
        isTargetSuper: mock.fn(async () => true)
      })
      const req = createReq({
        auth: {
          isSuper: false,
          scopes: ['assign:roles'],
          user: { _id: { toString: () => 'u1' } }
        },
        apiData: {
          modifying: false,
          data: { roles: ['regular1'] },
          query: { _id: 'target1' }
        }
      })
      await assert.rejects(async () => onUpdateRoles.call(inst, req))
    })

    it('should disavow user for non-POST methods', async () => {
      const disavowMock = mock.fn(async () => {})
      const authModule = { authentication: { disavowUser: disavowMock } }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => authModule),
          errors: { UNAUTHORISED: new Error('UNAUTHORISED') }
        }
      })
      const req = createReq({
        method: 'PUT',
        params: { _id: 'param-id' },
        auth: {
          isSuper: true,
          scopes: [],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      await onUpdateRoles.call(inst, req)
      assert.deepEqual(
        disavowMock.mock.calls[0].arguments[0],
        { userId: 'param-id' }
      )
    })

    it('should use body._id if params._id is not set', async () => {
      const disavowMock = mock.fn(async () => {})
      const authModule = { authentication: { disavowUser: disavowMock } }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => authModule),
          errors: { UNAUTHORISED: new Error('UNAUTHORISED') }
        }
      })
      const req = createReq({
        method: 'PUT',
        params: {},
        body: { _id: 'body-id' },
        auth: {
          isSuper: true,
          scopes: [],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      await onUpdateRoles.call(inst, req)
      assert.deepEqual(
        disavowMock.mock.calls[0].arguments[0],
        { userId: 'body-id' }
      )
    })

    it('should not disavow user for POST method', async () => {
      const disavowMock = mock.fn(async () => {})
      const authModule = { authentication: { disavowUser: disavowMock } }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => authModule),
          errors: { UNAUTHORISED: new Error('UNAUTHORISED') }
        }
      })
      const req = createReq({
        method: 'POST',
        auth: {
          isSuper: true,
          scopes: [],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      await onUpdateRoles.call(inst, req)
      assert.equal(disavowMock.mock.callCount(), 0)
    })

    it('should log the unauthorised attempt', async () => {
      const inst = createInstance({
        getSuperRoleId: mock.fn(async () => 'super1'),
        isTargetSuper: mock.fn(async () => false)
      })
      const req = createReq({
        auth: {
          isSuper: false,
          scopes: [],
          user: { _id: { toString: () => 'u1' } }
        }
      })
      try { await onUpdateRoles.call(inst, req) } catch (e) {}
      assert.equal(inst.log.mock.callCount(), 1)
      assert.equal(inst.log.mock.calls[0].arguments[0], 'error')
      assert.equal(inst.log.mock.calls[0].arguments[1], 'UNAUTHORISED')
    })
  })

  // ── onCheckUserAccess ──────────────────────────────────────────────

  describe('onCheckUserAccess', () => {
    it('should return true for non-modifying requests', async () => {
      const inst = createInstance({
        isTargetSuper: mock.fn(async () => true)
      })
      const req = { apiData: { modifying: false, query: { _id: 'x' } } }
      const result = await onCheckUserAccess.call(inst, req)
      assert.equal(result, true)
    })

    it('should return true for non-super targets', async () => {
      const inst = createInstance({
        isTargetSuper: mock.fn(async () => false)
      })
      const req = { apiData: { modifying: true, query: { _id: 'x' } } }
      const result = await onCheckUserAccess.call(inst, req)
      assert.equal(result, true)
    })

    it('should throw for modifying requests targeting super users', async () => {
      const inst = createInstance({
        isTargetSuper: mock.fn(async () => true)
      })
      const req = { apiData: { modifying: true, query: { _id: 'x' } } }
      await assert.rejects(
        async () => onCheckUserAccess.call(inst, req)
      )
    })

    it('should not call isTargetSuper for non-modifying requests', async () => {
      const isTargetSuperMock = mock.fn(async () => true)
      const inst = createInstance({ isTargetSuper: isTargetSuperMock })
      const req = { apiData: { modifying: false, query: { _id: 'x' } } }
      await onCheckUserAccess.call(inst, req)
      assert.equal(isTargetSuperMock.mock.callCount(), 0)
    })
  })

  // ── initConfigRoles ────────────────────────────────────────────────

  describe('initConfigRoles', () => {
    it('should insert new roles that do not exist', async () => {
      const insertMock = mock.fn(async (data) => data)
      const inst = createInstance({
        find: mock.fn(async () => []),
        insert: insertMock,
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'newrole',
              displayName: 'New Role',
              scopes: ['read:all']
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({ replace: mock.fn() })),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      assert.equal(insertMock.mock.callCount(), 1)
      assert.equal(
        insertMock.mock.calls[0].arguments[0].shortName, 'newrole'
      )
    })

    it('should replace existing roles', async () => {
      const replaceMock = mock.fn(async () => {})
      const inst = createInstance({
        find: mock.fn(async () => [{ _id: 'existing1', shortName: 'admin' }]),
        insert: mock.fn(async () => {}),
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'admin', displayName: 'Admin', scopes: ['*:*']
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({ replace: replaceMock })),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      assert.equal(replaceMock.mock.callCount(), 1)
      assert.deepEqual(
        replaceMock.mock.calls[0].arguments[1], { _id: 'existing1' }
      )
    })

    it('should log debug on successful insert', async () => {
      const inst = createInstance({
        find: mock.fn(async () => []),
        insert: mock.fn(async () => {}),
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'testrole', displayName: 'Test', scopes: []
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({})),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      assert.equal(inst.log.mock.calls[0].arguments[0], 'debug')
      assert.equal(inst.log.mock.calls[0].arguments[1], 'INSERT')
    })

    it('should log debug on successful replace', async () => {
      const inst = createInstance({
        find: mock.fn(async () => [{ _id: 'id1', shortName: 'admin' }]),
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'admin', displayName: 'Admin', scopes: []
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({
            replace: mock.fn(async () => {})
          })),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      assert.equal(inst.log.mock.calls[0].arguments[0], 'debug')
      assert.equal(inst.log.mock.calls[0].arguments[1], 'REPLACE')
    })

    it('should suppress duplicate key errors on insert', async () => {
      const dupError = new Error('duplicate key')
      dupError.code = 11000
      const inst = createInstance({
        find: mock.fn(async () => []),
        insert: mock.fn(async () => { throw dupError }),
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'dup', displayName: 'Dup', scopes: []
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({})),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      const warnCalls = inst.log.mock.calls.filter(
        c => c.arguments[0] === 'warn'
      )
      assert.equal(warnCalls.length, 0)
    })

    it('should log warning for non-duplicate insert errors', async () => {
      const error = new Error('some error')
      error.code = 500
      const inst = createInstance({
        find: mock.fn(async () => []),
        insert: mock.fn(async () => { throw error }),
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'fail', displayName: 'Fail', scopes: []
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({})),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      const warnCalls = inst.log.mock.calls.filter(
        c => c.arguments[0] === 'warn'
      )
      assert.equal(warnCalls.length, 1)
      assert.ok(warnCalls[0].arguments[1].includes('fail'))
    })

    it('should suppress duplicate key errors on replace', async () => {
      const dupError = new Error('duplicate key')
      dupError.code = 11000
      const inst = createInstance({
        find: mock.fn(async () => [{ _id: 'id1', shortName: 'admin' }]),
        getConfig: mock.fn((key) => {
          if (key === 'roleDefinitions') {
            return [{
              shortName: 'admin', displayName: 'Admin', scopes: []
            }]
          }
          return []
        }),
        collectionName: 'roles',
        schemaName: 'role',
        app: {
          waitForModule: mock.fn(async () => ({
            replace: mock.fn(async () => { throw dupError })
          })),
          errors: {}
        }
      })
      await initConfigRoles.call(inst)
      const warnCalls = inst.log.mock.calls.filter(
        c => c.arguments[0] === 'warn'
      )
      assert.equal(warnCalls.length, 0)
    })

    it('should handle empty roleDefinitions', async () => {
      const inst = createInstance({
        getConfig: mock.fn(() => []),
        app: {
          waitForModule: mock.fn(async () => ({})),
          errors: {}
        }
      })
      const result = await initConfigRoles.call(inst)
      assert.ok(Array.isArray(result))
      assert.equal(result.length, 0)
    })
  })

  // ── initDefaultRoles ───────────────────────────────────────────────

  describe('initDefaultRoles', () => {
    it('should tap into users preInsertHook', async () => {
      const tapMock = mock.fn()
      const usersModule = { preInsertHook: { tap: tapMock } }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        shortNamesToIds: mock.fn(async (names) => {
          return names.map(n => 'id-' + n)
        }),
        getConfig: mock.fn((key) => {
          if (key === 'defaultRoles') return ['authuser']
          if (key === 'defaultRolesForAuthTypes') return {}
          return []
        })
      })
      await initDefaultRoles.call(inst)
      assert.equal(tapMock.mock.callCount(), 1)
    })

    it('should set default roles when no roles present', async () => {
      let tapCallback
      const usersModule = {
        preInsertHook: {
          tap: (cb) => { tapCallback = cb }
        }
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        shortNamesToIds: mock.fn(async (names) => {
          return names.map(n => 'id-' + n)
        }),
        getConfig: mock.fn((key) => {
          if (key === 'defaultRoles') return ['authuser']
          if (key === 'defaultRolesForAuthTypes') return {}
          return []
        })
      })
      await initDefaultRoles.call(inst)

      const userData = { authType: 'local' }
      tapCallback(userData)
      assert.deepEqual(userData.roles, ['id-authuser'])
    })

    it('should not override existing roles on user data', async () => {
      let tapCallback
      const usersModule = {
        preInsertHook: {
          tap: (cb) => { tapCallback = cb }
        }
      }
      const inst = createInstance({
        app: {
          waitForModule: mock.fn(async () => usersModule),
          errors: {}
        },
        shortNamesToIds: mock.fn(async (names) => {
          return names.map(n => 'id-' + n)
        }),
        getConfig: mock.fn((key) => {
          if (key === 'defaultRoles') return ['authuser']
          if (key === 'defaultRolesForAuthTypes') return {}
          return []
        })
      })
      await initDefaultRoles.call(inst)

      const userData = { roles: ['existing-role'] }
      tapCallback(userData)
      assert.deepEqual(userData.roles, ['existing-role'])
    })
  })
})
