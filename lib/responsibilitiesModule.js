const AbstractApiModule = require('adapt-authoring-api');
/**
* Module which handles user management
* @extends {AbstractApiModule}
*/
class ResponsibilitiesModule extends AbstractApiModule {
  /** @override */
  async setValues() {
    /** @ignore */ this.root = 'responsibilities';
    /** @ignore */ this.schemaName = 'responsibility';
    /** @ignore */ this.collectionName = 'responsibilities';

    this.useDefaultRouteConfig();
  }
}

module.exports = ResponsibilitiesModule;
