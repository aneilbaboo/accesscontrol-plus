// tslint:disable-next-line
export type Context = any;
export type Condition = (context: Context) => boolean;
export const All: Condition = () => true;

export interface IMap<T> {
  [name: string]: T;
}

export interface IRole {
  resources: IMap<IResource>;
  inherits: string[];
}

export interface IScope {
  condition: Condition;
}

export type IResource = IMap<IScope>;

export type IGrants = IMap<IRole>;

export class RBACPlus {
  constructor(public grants: IGrants = {}) {}

  public grant(roleName: string) {
    if (!this.grants[roleName]) {
      this.grants[roleName] = { resources: {}, inherits: []};
    }
    return new Role(this.grants, roleName);
  }

  /**
   * Tests whether one or more roles is authorized to perform the request with the given requirements
   * E.g., rbac.can('user', 'Report:update', { ownerId: 'auth0|1234' }, { userId: 'auth0|1234' })
   *   // tests whether 'user' role can 'Report:update' for resource having ownerId='auth0|1234'
   *   // given a request context { userId: 'auth0|1234' }
   * @param roleName
   * @param scope - the permission being sought ({resource}:{action})
   * @param context - Arbitrary object providing values resolved by the where Conditions
   */
  public can(roleNames: string | string[], scope: string, context: Context) {
    const [resourceName, actionName] = scope.split(':');
    if (typeof roleNames === 'string') {
      return this.canRole(roleNames, resourceName, actionName, context);
    } else {
      return roleNames.some(roleName => this.canRole(roleName, resourceName, actionName, context));
    }
  }

  private canRole(roleName: string, resourceName: string, actionName: string, context: Context): boolean {
    const role: IRole = this.grants[roleName];
    let result = false;
    if (role) {
      const roleResource = role.resources[resourceName];
      if (roleResource) {
        const scope = roleResource[actionName];
        const condition = scope && scope.condition;
        if (condition) {
          try {
            if (condition(context)) {
              return true;
            }
          } catch (e) {
            // no action
          }
        }
      }

      if (role.inherits &&
          role.inherits.some(parentRoleName => this.canRole(parentRoleName, resourceName, actionName, context))) {
          return true;
      }

      if (resourceName !== '*' && this.canRole(roleName, '*', actionName, context)) {
        return true;
      }

      if (actionName !== '*' && this.canRole(roleName, resourceName, '*', context)) {
        return true;
      }
    }
    return result;
  }
}
export class Role extends RBACPlus {
  constructor(grants: IGrants, public readonly roleName: string) {
    super(grants);
  }

  public inherits(roleName: string) {
    if (this._role.inherits) {
      this._role.inherits.push(roleName);
    } else {
      this._role.inherits = [roleName];
    }
    return this;
  }

  // public permission(scope: string, where: any = All): Permission {
  //   const [resource, operation] = scope.split(':');
  //   return this.resource(resource).permission(operation, where);
  // }

  public resource(resourceName: string): Resource {
    if (!this._role.resources.hasOwnProperty(resourceName)) {
      this._role.resources[resourceName] = {};
    }

    return new Resource(this.grants, this.roleName, resourceName);
  }

  /**
   * Shortcut for .resource('resourceName').scope('actionName')
   *
   * @param scope '{resourceName}:{actionName}'
   * @returns {Scope}
   */
  public scope(scope: string): Scope {
    const [resource, action] = scope.split(':');
    return this.resource(resource).scope(action);
  }

  protected get _role(): IRole {
    return this.grants[this.roleName];
  }
}

export class Resource extends Role {
  constructor(grants: IGrants, roleName: string, public readonly resourceName: string) {
    super(grants, roleName);
  }

  public action(actionName: string): Scope {
    this._resource[actionName] = this._resource[actionName] || { condition: All };
    return new Scope(this.grants, this.roleName, this.resourceName, actionName);
  }

  protected get _resource(): IResource {
    return this.grants[this.roleName].resources[this.resourceName];
  }
}

export class Scope extends Resource {
  constructor(grants: IGrants, roleName: string, resourceName: string, public readonly actionName: string) {
    super(grants, roleName, resourceName);
  }

  public where(...conditions: Condition[]): Scope {
    return this.and(...conditions);
  }

  public or(...conditions: Condition[]): Scope {
    const prevCondition = this.condition;
    if (prevCondition === All) {
      this._condition = ({...options}) => conditions.some(c => c(options));
    } else {
      this._condition = ({...options}) => prevCondition(options) || conditions.some(c=> c(options));
    }
    return this;
  }

  public and(...conditions: Condition[]): Scope {
    const prevCondition = this.condition;
    if (prevCondition === All) {
      this._condition = ({...options}) => conditions.every(c => c(options));
    } else {
      this._condition = ({...options}) => prevCondition(options) && conditions.every(c=> c(options));
    }

    return this;
  }

  public get condition(): Condition {
    return this._scope.condition;
  }

  private set _condition(value: Condition) {
    this._scope.condition = value;
  }

  protected get _scope(): IScope {
    return this._resource[this.actionName];
  }
}
