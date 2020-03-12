const AbstractApiModule = require('adapt-authoring-api');
/**
* Module which handles user roles
* @extends {AbstractApiModule}
*/
class RolesModule extends AbstractApiModule {
  /** @override */
  async setValues() {
    /** @ignore */ this.root = 'roles';
    /** @ignore */ this.schemaName = 'role';
    /** @ignore */ this.collectionName = 'roles';

    this.useDefaultRouteConfig();
  }
}

module.exports = RolesModule;
