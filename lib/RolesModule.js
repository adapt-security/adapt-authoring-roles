const AbstractApiModule = require('adapt-authoring-api');
/**
 * Module which handles user roles
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
  }
  /**
   * Adds any role definitions from the current config file to the database
   * @return {Promise}
   */
  async initConfigRoles() {
    return Promise.allSettled(this.getConfig('roleDefinitions').map(async r => {
      const [doc] = await this.find({ shortName: r.shortName });
      if(doc) {
        try {
          await this.update({ _id: doc._id }, r);
          this.log('debug', `updated '${r.shortName}' role in database`);
        } catch(e) {
          if(e.code !== 11000) this.log('warn', `failed to update '${r.shortName}' role, ${e.message}`);
        }
        return;
      }
      try {
        await this.insert(r);
        this.log('debug', `added '${r.shortName}' role to database`);
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

    const d = this.getConfig('defaultRolesForAuthTypes');
    const ids = await Promise.all(Object.values(d).map(this.shortNamesToIds, this));
    const authRoles = Object.keys(d).reduce((m,t,i) => Object.assign(m, { [t]: ids[i] }), {});
    const roles = await this.shortNamesToIds(this.getConfig('defaultRoles'));
    const users = await this.app.waitForModule('users');

    users.insertHook.tap(data => {
      const type = data.authTypes[0];
      if(!data.roles) data.roles = [];
      const r = authRoles[type] || roles[type] || [];
      data.roles.push(...r);
    });
  }
  /** @override */
  async setValues() {
    /** @ignore */ this.root = 'roles';
    /** @ignore */ this.schemaName = 'role';
    /** @ignore */ this.collectionName = 'roles';
    this.useDefaultRouteConfig();
  }
}

module.exports = RolesModule;
