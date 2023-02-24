import AbstractApiModule from 'adapt-authoring-api';
/**
 * Module which handles user roles
 * @memberof roles
 * @extends {AbstractApiModule}
 */
class RolesModule extends AbstractApiModule {
  /** @override */
  async init() {
    await super.init();
    try {
      await this.initConfigRoles();

      const hasRoles = this.getConfig('defaultRolesForAuthTypes').length || this.getConfig('defaultRoles').length;
      if(hasRoles) await this.initDefaultRoles();
    } catch(e) {
      this.log('error', e);
    }
    const [localauth, users] = await this.app.waitForModule('localauth', 'users');
    localauth.registerHook.tap(this.onUpdateRoles.bind(this));
    users.requestHook.tap(this.onUpdateRoles.bind(this));
  }
  /**
   * Adds any role definitions from the current config file to the database
   * @return {Promise}
   */
  async initConfigRoles() {
    const mongodb = await this.app.waitForModule('mongodb');
    return Promise.allSettled(this.getConfig('roleDefinitions').map(async r => {
      const [doc] = await this.find({ shortName: r.shortName });
      if(doc) {
        try {
          await mongodb.replace(this.collectionName, { _id: doc._id }, r);
          this.log('debug', 'REPLACE', this.schemaName, r.shortName);
        } catch(e) {
          if(e.code !== 11000) this.log('warn', `failed to update '${r.shortName}' role, ${e.message}`);
        }
        return;
      }
      try {
        await this.insert(r);
        this.log('debug', 'INSERT', this.schemaName, r.shortName);
      } catch(e) {
        if(e.code !== 11000) this.log('warn', `failed to add '${r.shortName}' role, ${e.message}`);
      }
    }));
  }
  /**
   * Adds the specified default roles during new user creation
   * @return {Promise}
   */
  async shortNamesToIds(roles) {
    return Promise.all(roles.map(async r => {
      let role = this.roleCache[r];
      if(!role) {
        [role] = await this.find({ shortName: r });
        this.roleCache[r] = role;
      }
      return role._id.toString();
    }));
  }
  /**
   * Handles setting defined default roles when new users are added
   * @return {Promise}
   */
  async initDefaultRoles() {
    /**
     * Local store of roles
     * @type {Object}
     */
    this.roleCache = {};

    const rolesforAll = await this.shortNamesToIds(this.getConfig('defaultRoles'));
    const rolesForAuth = Object.entries(this.getConfig('defaultRolesForAuthTypes')).reduce((m,[k,v]) => {
      return { [m[k]]: this.shortNamesToIds(v) };
    }, {});
    const users = await this.app.waitForModule('users');
    users.preInsertHook.tap(data => {
      if(!data.roles || !data.roles.length) {
        data.roles = rolesForAuth[data.authType] || rolesforAll || [];
      }
    });
  }
  /** @override */
  async setValues() {
    /** @ignore */ this.root = 'roles';
    /** @ignore */ this.schemaName = 'role';
    /** @ignore */ this.collectionName = 'roles';
    this.useDefaultRouteConfig();
  }
  /**
   * Handler for requests which attempt to update roles
   * @param {external:ExpressRequest} req 
   * @returns {Promise}
   */
  async onUpdateRoles(req) {
    if(!req.body.roles || req.method === 'GET' || req.method === 'DELETE') {
      return;
    }
    if(!req.auth.isSuper && !req.auth.scopes.includes('assign:roles')) {
      this.log('error', 'User does not have the correct permissions to assign user roles');
      throw this.app.errors.UNAUTHORISED;
    }
    if(req.method !== 'POST') {
      const auth = await this.app.waitForModule('auth');
      await auth.authentication.disavowUser({ userId: req.params._id || req.body._id });
    }
  }
}

export default RolesModule;