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
      let role = this.roleCache[r]
      if (!role) {
        [role] = await this.find({ shortName: r })
        this.roleCache[r] = role
      }
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
    /**
     * Local store of roles
     * @type {Object}
     */
    this.roleCache = {}

    const rolesforAll = await this.shortNamesToIds(this.getConfig('defaultRoles'))
    const rolesForAuth = Object.entries(this.getConfig('defaultRolesForAuthTypes')).reduce((m, [k, v]) => {
      return { [m[k]]: this.shortNamesToIds(v) }
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
    if (!req.body.roles || req.method === 'GET' || req.method === 'DELETE') {
      return
    }
    if (!req.auth.isSuper && !req.auth.scopes.includes('assign:roles')) {
      this.log('error', 'User does not have the correct permissions to assign user roles')
      throw this.app.errors.UNAUTHORISED
    }
    if (req.method !== 'POST') {
      const auth = await this.app.waitForModule('auth')
      await auth.authentication.disavowUser({ userId: req.params._id || req.body._id })
    }
  }

  /**
   * Blocks modification of super users by non-super users
   * @param {external:ExpressRequest} req
   * @param {Object} data Request data
   */
  async onCheckUserAccess (req, data) {
    if (['GET', 'POST'].includes(req.method)) {
      return true
    }
    const users = await this.app.waitForModule('users')
    const [user] = await users.find({ _id: req.apiData.query._id })
    const scopes = user.roles.length === 1 ? await this.getScopesForRole(user.roles[0]) : []
    const isSuper = scopes.length === 1 && scopes[0] === '*:*'
    if (isSuper && !req.auth.isSuper) {
      throw this.app.errors.UNAUTHORISED
    }
  }
}

export default RolesModule
