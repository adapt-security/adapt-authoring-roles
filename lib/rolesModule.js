const AbstractApiModule = require('adapt-authoring-api');
/**
* Module which handles user roles
* @extends {AbstractApiModule}
*/
class RolesModule extends AbstractApiModule {
  /** @override */
  async init() {
    const [jsonschema, mongodb] = await this.app.waitForModule('jsonschema', 'mongodb');
    jsonschema.extendSchema('user', 'userroles');

    await mongodb.setUniqueIndex(this.collectionName, 'shortName');

    await this.initConfigRoles();

    if(this.getConfig('defaultRoles')) {
      await this.initDefaultRoles();
    }
    return super.init();
  }
  /**
  * Adds any role definitions from the current config file to the database
  * @return {Promise}
  */
  async initConfigRoles() {
    return Promise.allSettled(this.getConfig('roleDefinitions').map(r => {
      return this.insert(r)
        .catch(e => e.code !== 11000 && this.log('warn', `Failed to add '${r.shortName}' role, ${e.message}`));
    }));
  }
  /**
  * Adds the specified default roles during new user creation
  * @return {Promise}
  */
  async initDefaultRoles() {
    const shortNames = this.getConfig('defaultRoles').map(r => Object.assign({ shortName: r }));
    const defaultRoles = (await this.find({ $or: shortNames })).map(r => r._id.toString());
    const users = await this.app.waitForModule('users');

    users.insertHook.tap(data => {
      if(!data.roles) data.roles = [];
      data.roles.push(...defaultRoles);
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
