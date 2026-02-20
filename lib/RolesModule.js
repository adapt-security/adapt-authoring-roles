import AbstractApiModule from 'adapt-authoring-api'
/**
 * Module which handles user roles
 * @memberof roles
 * @extends {AbstractApiModule}
 */
class RolesModule extends AbstractApiModule {
  /** @override */
  async init () {
    await super.init()
    this.cache.isEnabled = true
    try {
      await this.initConfigRoles()

      const hasRoles = this.getConfig('defaultRolesForAuthTypes').length || this.getConfig('defaultRoles').length
      if (hasRoles) await this.initDefaultRoles()
    } catch (e) {
      this.log('error', e)
    }
    const [authlocal, users] = await this.app.waitForModule('auth-local', 'users')
    authlocal.registerHook.tap(this.onUpdateRoles.bind(this))
    users.requestHook.tap(this.onUpdateRoles.bind(this))
    users.accessCheckHook.tap(this.onCheckUserAccess, this)
  }

  /**
   * Adds any role definitions from the current config file to the database
   * @return {Promise}
   */
  async initConfigRoles () {
    const mongodb = await this.app.waitForModule('mongodb')
    return Promise.allSettled(this.getConfig('roleDefinitions').map(async r => {
      const [doc] = await this.find({ shortName: r.shortName })
      if (doc) {
        try {
          await mongodb.replace(this.collectionName, { _id: doc._id }, r)
          this.log('debug', 'REPLACE', this.schemaName, r.shortName)
        } catch (e) {
          if (e.code !== 11000) this.log('warn', `failed to update '${r.shortName}' role, ${e.message}`)
        }
        return
      }
      try {
        await this.insert(r)
        this.log('debug', 'INSERT', this.schemaName, r.shortName)
      } catch (e) {
        if (e.code !== 11000) this.log('warn', `failed to add '${r.shortName}' role, ${e.message}`)
      }
    }))
  }

  /**
   * Adds the specified default roles during new user creation
   * @return {Promise}
   */
  async shortNamesToIds (roles) {
    return Promise.all(roles.map(async r => {
      const [role] = await this.find({ shortName: r })
      return role._id.toString()
    }))
  }

  /**
   * Returns the list of scopes for the given role
   * @param {String | ObjectId} _id The _id of the role
   * @returns {Array<String>} Array of scopes
   */
  async getScopesForRole (_id) {
    const allRoles = await this.find()
    const scopes = []
    let role = allRoles.find(r => r._id.toString() === _id.toString())
    do {
      scopes.push(...role.scopes)
      role = allRoles.find(r => r.shortName === role.extends)
    } while (role)
    return scopes
  }

  /**
   * Handles setting defined default roles when new users are added
   * @return {Promise}
   */
  async initDefaultRoles () {
    const rolesforAll = await this.shortNamesToIds(this.getConfig('defaultRoles'))
    const rolesForAuth = Object.entries(this.getConfig('defaultRolesForAuthTypes')).reduce((m, [k, v]) => {
      return { ...m, [k]: this.shortNamesToIds(v) }
    }, {})
    const users = await this.app.waitForModule('users')
    users.preInsertHook.tap(data => {
      if (!data.roles || !data.roles.length) {
        data.roles = rolesForAuth[data.authType] || rolesforAll || []
      }
    })
  }

  /** @override */
  async setValues () {
    /** @ignore */ this.root = 'roles'
    /** @ignore */ this.schemaName = 'role'
    /** @ignore */ this.collectionName = 'roles'
    this.useDefaultRouteConfig()
  }

  /**
   * Handler for requests which attempt to update roles
   * @param {external:ExpressRequest} req
   * @returns {Promise}
   */
  async onUpdateRoles (req) {
    if (req.apiData?.modifying !== false || (req.method !== 'DELETE' && !req.apiData?.data.roles)) {
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
      await auth.authentication.disavowUser({ userId: req.params._id || req.body._id })
    }
  }

  async onCheckUserAccess (req) { // note access checks don't run for super users
    if (req.apiData.modifying && await this.isTargetSuper(req.apiData.query._id)) {
      throw this.app.errors.UNAUTHORISED
    }
    return true
  }

  async getSuperRoleId () {
    const [superRole] = await this.find({ scopes: ['*:*'] })
    return superRole._id.toString()
  }

  async isTargetSuper (_id) {
    const users = await this.app.waitForModule('users')
    const [user] = await users.find({ _id }, { projection: { roles: 1 } })
    return user.roles.length === 1 && user.roles[0].toString() === await this.getSuperRoleId()
  }
}

export default RolesModule
