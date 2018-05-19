export type Context = any; // tslint:disable-line
export type Constraint = any; // tslint:disable-line
export type ConstraintGenerator = (context: Context) => any; // tslint:disable-line
export type Condition = (context: Context) => boolean;
export function All() { return true; }

export interface IMap<T> {
  [name: string]: T;
}

export interface IRole {
  resources: IMap<IResource>;
  inherits?: string[];
}

export type Effect = 'grant' | 'deny';

export interface IScope {
  condition: Condition;
  constraint: ConstraintGenerator;
  effect: Effect;
}

export type IRequest = string;

export interface IPermission {
  granted?: IRequest;
  denied?: IRequest[];
  constraint?: Constraint;
}

export type IResource = IMap<IScope>;
export type IRoles = IMap<IRole>;

export class RBACPlus {
  constructor(public roles: IRoles = {}) {}

  public grant(roleName: string) {
    this.ensureRole(roleName);
    return new Role(this.roles, roleName, 'grant');
  }

  public deny(roleName: string) {
    this.ensureRole(roleName);
    return new Role(this.roles, roleName, 'deny');
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
  public async can(roleName: string, scope: string, context: Context): Promise<IPermission> {
    const [resourceName, actionName] = scope.split(':');
    let permission: IPermission = {};
    await this.canRole(roleName, resourceName, actionName, context, permission);
    return permission;
  }

  private async canRole(
    roleName: string,
    resourceName: string,
    actionName: string,
    context: Context,
    permission: IPermission): Promise<boolean> {

      const role: IRole = this.roles[roleName] || this.roles['*'];
      if (!role) {
        return false;
      }

      const roleResource = role.resources[resourceName] || role.resources['*'];

      if (roleResource) {
        const scope = roleResource[actionName] || roleResource['*'];
        if (scope) {
          const description = [roleName, resourceName, actionName, scope.condition.name].join(':');
          const [returnValue, terminate] = await this.processScope(scope, context, description, permission);
          if (terminate) {
            return returnValue;
          }
        }
      }

      if (role.inherits) {
        for (const inheritedRole of role.inherits) {
          if (this.canRole(inheritedRole, resourceName, actionName, context, permission)) {
            return true;
          }
        }
      }

      return false;
    }

    private ensureRole(roleName: string) {
      if (!this.roles[roleName]) {
        this.roles[roleName] = { resources: {} };
      }
    }

    private addDenial(permission: IPermission, description: string) {
      if (!permission.denied) {
        permission.denied = [description];
      } else {
        permission.denied.push(description);
      }
    }

    /**
     *
     * @param condition
     * @param context
     * @returns test passed or failed
     */
    private async testCondition(condition: Condition, context: Context): Promise<boolean> {
      try {
        return await condition(context);
      } catch (e) {
        return false;
      }
    }

  /**
   * Process a result of a condition, updating the permission and returning the effective value
   * of the test (true = permission granted, false = permission denied)
   *
   * @private
   * @param {boolean} conditionValue
   * @param {Effect} effect
   * @param {string} description
   * @param {IPermission} permission
   * @returns {Array<boolean, boolean>} effectiveValue, terminate
   * @memberof RBACPlus
   */
  private async processScope(
    scope: IScope, context: Context, description: string, permission: IPermission
  ): Promise<[boolean, boolean]> {
    let conditionValue = await this.testCondition(scope.condition, context);
    if (scope.effect === 'grant') {
      if (conditionValue) {
        permission.granted = description;
        if (scope.constraint) {
          permission.constraint = scope.constraint(context);
        }
        return [true, conditionValue];
      } else { // failed to grant:
        this.addDenial(permission, description);
      }
    } else { // effect === 'deny'
      if (conditionValue) { // explicitly denied
        this.addDenial(permission, description);
        return [false, true];
      } // else: do nothing if deny failed
    }
    return [false, false];
  }
}

export class Role extends RBACPlus {
  constructor(roles: IRoles, public readonly roleName: string, public readonly effect: Effect = 'grant') {
    super(roles);
  }

  public inherits(roleName: string) {
    const superRoles = this._role.inherits;
    if (superRoles) {
      if (superRoles.includes(roleName)) {
        superRoles.push(roleName);
      }
    } else {
      this._role.inherits = [roleName];
    }
    return this;
  }

  public resource(resourceName: string): Resource {
    if (!this._role.resources.hasOwnProperty(resourceName)) {
      this._role.resources[resourceName] = {};
    }

    return new Resource(this.roles, this.roleName, this.effect, resourceName);
  }

  /**
   * Shortcut for .resource('resourceName').scope('actionName')
   *
   * @param scope '{resourceName}:{actionName}'
   * @returns {Scope}
   */
  public scope(scope: string): Scope {
    const [resource, action] = scope.split(':');
    return this.resource(resource).action(action);
  }

  protected get _role(): IRole {
    return this.roles[this.roleName];
  }
}

export class Resource extends Role {
  constructor(roles: IRoles, roleName: string, effect: Effect, public readonly resourceName: string) {
    super(roles, roleName);
  }

  public action(actionName: string): Scope {
    this._resource[actionName] = this._resource[actionName] || {
      condition: All,
      constraints: {},
      effect: this.effect
    };
    return new Scope(this.roles, this.roleName, this.effect, this.resourceName, actionName);
  }

  protected get _resource(): IResource {
    return this.roles[this.roleName].resources[this.resourceName];
  }
}

export class Scope extends Resource {
  constructor(
    roles: IRoles, roleName: string, effect: Effect, resourceName: string, public readonly actionName: string) {
    super(roles, roleName, effect, resourceName);
  }

  public withConstraint(constraint: Constraint): Scope {
    this._scope.constraint = constraint;
    return this;
  }

  public where(...conditions: Condition[]): Scope {
    if (conditions.length === 1) {
      this._condition = conditions[0];
      return this;
    } else {
      return this.and(...conditions);
    }
  }

  public or(...conditions: Condition[]): Scope {
    const prevCondition = this.condition;
    const testConditions = prevCondition === All ? conditions : [All, ...conditions];
    // dynamically name function:
    const name = `or(${conditions.map(c => c.name || 'unknownCondition').join(',')}`;
    this._condition = { [name]: ({...options}) => testConditions.some(c => c(options)) }[name];
    return this;
  }

  public and(...conditions: Condition[]): Scope {
    const prevCondition = this.condition;
    const testConditions = prevCondition === All ? conditions : [All, ...conditions];
    // dynamically name function:
    const name = `and(${conditions.map(c => c.name || 'unknownCondition').join(',')}`;
    this._condition = { [name]: ({...options}) => testConditions.every(c => c(options)) }[name];

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
