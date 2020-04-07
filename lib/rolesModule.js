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

    Promise.all(this.getConfig('defaultRoles').map(r => this.insert(r)));

    return super.init();
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
