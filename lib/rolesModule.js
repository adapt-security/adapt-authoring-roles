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

    await this.initDefaultRoles();

    return super.init();
  }
  async initDefaultRoles() {
    return Promise.allSettled(this.getConfig('defaultRoles').map(r => {
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
}

module.exports = RolesModule;
