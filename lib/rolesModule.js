const AbstractApiModule = require('adapt-authoring-api');
/**
* Module which handles user roles
* @extends {AbstractApiModule}
*/
class RolesModule extends AbstractApiModule {
  /** @override */
  async init() {
    const jsonschema = await this.app.waitForModule('jsonschema');
    jsonschema.extendSchema('user', 'userroles');
    super.init();
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
