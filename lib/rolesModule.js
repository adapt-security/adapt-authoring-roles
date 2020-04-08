const AbstractApiModule = require('adapt-authoring-api');
/**
* Module which handles user roles
* @extends {AbstractApiModule}
*/
class RolesModule extends AbstractApiModule {
  /** @override */
  async init() {
    const [jsonschema, mongodb, users] = await this.app.waitForModule('jsonschema', 'mongodb', 'users');
    jsonschema.extendSchema('user', 'userroles');

    await mongodb.setUniqueIndex(this.collectionName, 'shortName');

    await this.initConfigRoles();

    if(this.getConfig('defaultRoles')) {
      this.defaultRoles = (await this.find({ shortName: { $OR: this.getConfig('defaultRoles') } })).map(r => r._id);
      users.requestHook.tap(this.setDefaultRoles.bind(this));
    }
    return super.init();
  }
  async initConfigRoles() {
    return Promise.allSettled(this.getConfig('roleDefinitions').map(r => {
      return this.insert(r)
        .catch(e => e.code !== 11000 && this.log('warn', `Failed to add '${r.shortName}' role, ${e.message}`));
    }));
  }
  /** @override */
  async setValues() {
    /** @ignore */ this.root = 'roles';
    /** @ignore */ this.schemaName = 'role';
    /** @ignore */ this.collectionName = 'roles';

    this.useDefaultRouteConfig();
  }
  async setDefaultRoles(req) {
    req.body.roles.push(...this.defaultRoles);
  }
}

module.exports = RolesModule;
