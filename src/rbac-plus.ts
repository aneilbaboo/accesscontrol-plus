/// <reference path="./interfaces.ts" />
/// <reference path="./permission.ts" />
import { isArray } from 'util';
import {
  IRoleDef, IMap, IRoleDefs, IScopeDef, IResourceDef,
  ICondition, IConstraint, IContext,
  IEffect, IExplanation,
  IFieldDefs, IFieldGenerator, IFieldTest,
  IPermission
} from './interfaces';
import { Permission } from './permission';

export function All() { return true; }

export class RBACPlus {
  constructor(public roles: IRoleDefs = {}) {}

  public grant(roleName: string): Role {
    this.ensureRole(roleName);
    return new Role(this.roles, roleName, 'grant');
  }

  public deny(roleName: string): Role {
    this.ensureRole(roleName);
    return new Role(this.roles, roleName, 'deny');
  }

  /**
   * Tests whether one or more roles is authorized to perform the request with the given requirements
   * E.g., rbac.can('user', 'Report:update', { ownerId: 'auth0|1234' }, { userId: 'auth0|1234' })
   *   // tests whether 'user' role can 'Report:update' for resource having ownerId='auth0|1234'
   *   // given a request context { userId: 'auth0|1234' }
   *
   * @param {(string | string[])} roleNames
   * @param {string} scope
   * @param {IContext} [context]
   * @returns {Promise<IPermission>}
   * @memberof RBACPlus
   */
  public async can(roleNames: string | string[], scope: string, context?: IContext): Promise<IPermission> {
    const [resourceName, actionName, field] = scope.split(':');
    let permission = new Permission();
    roleNames = isArray(roleNames) ? roleNames : [roleNames];
    for (const roleName of roleNames) {
      await this.canRole(roleName, resourceName, actionName, field, context, permission);
      if (permission.granted) {
        break;
      }
    }
    return permission;
  }

  private getWithDefaultWildcard<T>(key: string, obj: IMap<T>): [string, T] {
    let value = obj[key];
    if (value) {
      return [key, value];
    } else {
      return ['*', obj['*']];
    }
  }

  private async canRole(
    roleName: string,
    resourceName: string,
    actionName: string,
    field: string,
    context: IContext,
    permission: Permission): Promise<boolean> {
      let role: IRoleDef, resource: IResourceDef, action: IScopeDef[];
      let testedRoleName, testedResourceName, testedActionName;
      [testedRoleName, role]  = this.getWithDefaultWildcard(roleName, this.roles);
      if (role) {
        [testedResourceName, resource] = this.getWithDefaultWildcard(resourceName, role.resources);

        if (resource) {
          [testedActionName, action] = this.getWithDefaultWildcard(actionName, resource);
          if (action) {
            const actionPath = `${testedRoleName}:${testedResourceName}:${testedActionName}`;
            const [granted, terminate] = await this.canAction(action, actionPath, field, context, permission);
            if (terminate) {
              return granted;
            }
          }
        }

        if (role.inherits) {
          for (const inheritedRole of role.inherits) {
            if (await this.canRole(inheritedRole, resourceName, actionName, field, context, permission)) {
              return true;
            }
          }
        }

        permission.deny();
      }

      return false;
    }

    private ensureRole(roleName: string) {
      if (!this.roles[roleName]) {
        this.roles[roleName] = { resources: {} };
      }
    }

    /**
     *
     * @param condition
     * @param context
     * @returns test passed or failed
     */
    private async testCondition(condition: ICondition, context: IContext): Promise<boolean> {
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
   * @param {IEffect} effect
   * @param {string} scopeRequest
   * @param {Permission} permission
   * @returns {Array<boolean, boolean>} granted, terminate
   * @memberof RBACPlus
   */
  private async canAction(
    action: IScopeDef[], actionPath: string, field: string | void, context: IContext, permission: Permission
  ): Promise<[boolean, boolean]> {
    let granted, terminate = false;
    let scopeIndex = 0;
    for (const scope of action) {
      const scopePath = `${scope.effect}:${actionPath}:${scopeIndex}`;
      [granted, terminate] = await this.canScope(scope, scopePath, field, context, permission);
      if (terminate) {
        return [granted, terminate];
      }
      scopeIndex++;
    }

    return [false, false];
  }

  private async canScope(
    scope: IScopeDef,
    scopePath: string,
    field: string |  void,
    context: IContext,
    permission: Permission
  ): Promise<[boolean, boolean]> {
    if (scope.effect === 'grant') {
      return await this.canGrantScope(scope, scopePath, field, context, permission);
    } else { // effect === 'deny'
      return await this.canDenyScope(scope, scopePath, field, context, permission);
    }
  }

  private async canGrantScope(
    scope: IScopeDef,
    scopePath: string,
    field: string | void,
    context: IContext,
    permission: Permission
  ): Promise<[boolean, boolean]> {
    const [success, fields, permissionPath] = await this.testScope(scope, scopePath, field, context);
    if (success) {
      const constraint = (scope.constraint instanceof Function ?
        await scope.constraint(context)
        : scope.constraint
      );
      permission.grant(permissionPath, fields, constraint);
      return [true, true];
    } else { // failed to grant:
      permission.deny(permissionPath, fields);
      return [false, false];
    }
  }

  private async canDenyScope(
    scope: IScopeDef,
    scopePath: string,
    field: string | void,
    context: IContext,
    permission: Permission
  ): Promise<[boolean, boolean]> {
    const [success, fields, permissionPath] = await this.testScope(scope, scopePath, field, context);
    if (success) {
      permission.deny(permissionPath, fields);
      return [false, true]; // explicitly denied
    } else {
      return [false, false]; // failed to deny
    }
  }

  private async testScope(
    scope: IScopeDef,
    scopePath: string,
    field: string | void,
    context: IContext
  ): Promise<[boolean, IMap<boolean>, string]> {
    const fields = await this.generateFields(scope, context);
    const [matchedField, fieldTest] = field ? Permission.testField(field, fields) :  [undefined, true];
    const conditionTest = fieldTest && await this.testCondition(scope.condition, context);
    const permissionPath = this.permissionPath(scopePath, matchedField, fieldTest, scope.condition);
    const success = !!(fieldTest && conditionTest);
    return [success, fields, permissionPath];
  }

  private permissionPath(scopePath: string, field: string | void, fieldTest: boolean, condition: ICondition | void) {
    const conditionName = fieldTest ? (condition ? condition.name || 'unnamedCondition' : '') : '';
    return `${scopePath}:${field ? field : ''}:${conditionName}`;
  }

  private async generateFields(scope: IScopeDef, context: IContext): Promise<IFieldDefs> {
    if (scope.fieldGenerator) {
      return await scope.fieldGenerator(context);
    } else {
      return {};
    }
  }
}

export class Role extends RBACPlus {
  constructor(roles: IRoleDefs, public readonly roleName: string, public readonly effect: IEffect) {
    super(roles);
  }

  public inherits(roleName: string) {
    const superRoles = this._role.inherits;
    if (superRoles) {
      if (!superRoles.includes(roleName)) {
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

  protected get _role(): IRoleDef {
    return this.roles[this.roleName];
  }
}

export class Resource extends Role {
  constructor(roles: IRoleDefs, roleName: string, effect: IEffect, public readonly resourceName: string) {
    super(roles, roleName, effect);
  }

  public action(actionName: string): Scope {
    if (!this._resource[actionName]) {
      this._resource[actionName] = [];
    }
    const scopes = this._resource[actionName];
    const scopeIndex = scopes.length;
    scopes.push({
      condition: All,
      constraint: {},
      effect: this.effect
    });
    return new Scope(this.roles, this.roleName, this.effect, this.resourceName, actionName, scopeIndex);
  }

  public get create(): Scope {
    return this.action('create');
  }

  public get read(): Scope {
    return this.action('read');
  }

  public get update(): Scope {
    return this.action('update');
  }

  public get delete(): Scope {
    return this.action('delete');
  }

  protected get _resource(): IResourceDef {
    return this.roles[this.roleName].resources[this.resourceName];
  }
}

export class Scope extends Resource {
  constructor(
    roles: IRoleDefs, roleName: string, effect: IEffect, resourceName: string,
    public readonly actionName: string,
    public readonly scopeIndex: number) {
    super(roles, roleName, effect, resourceName);
  }

  public withConstraint(constraint: IConstraint): Scope {
    this._scope.constraint = constraint;
    return this;
  }

  /**
   * Generate acceptable fields dynamically, based on the context
   * E.g.,
   * ```scope.onDynamicFields((ctx: IContext) => {
   *   if (ctx.userHasFullAccess) {
   *     return { '*': true };
   *   } else {
   *     return { '*': true, 'privateData': false };
   *   }
   * });
   * ```
   *
   * @param {IFieldGenerator} fieldGen
   * @returns {Scope}
   * @memberof Scope
   */
  public onDynamicFields(fieldGen: IFieldGenerator): Scope {
    this._scope.fieldGenerator = fieldGen;
    return this;
  }

  /**
   * Adds a fieldTest to this scope
   * E.g., `scope.onFields('*', '!privateData')`
   *
   * @param {...string[]} fieldNames
   * @memberof Scope
   */
  public onFields(... fieldNames: string[]): Scope {
    const fnameRE = /^([!]?)(.+)/;
    const fieldMap: IMap<boolean> = {};

    for (const field of fieldNames) {
      const match = fnameRE.exec(field);
      if (!match) {
        throw new Error(`Invalid field name: ${field}`);
      } else {
        fieldMap[match[2]] = match[1] !== '!';
      }
    }

    this._scope.fieldGenerator = (context: IContext) => fieldMap;
    return this;
  }

  public where(...conditions: ICondition[]): Scope {
    if (conditions.length === 1) {
      this._condition = conditions[0];
      return this;
    } else {
      return this.and(...conditions);
    }
  }

  public or(...conditions: ICondition[]): Scope {
    const prevCondition = this.condition;
    const testConditions = prevCondition === All ? conditions : [All, ...conditions];
    // dynamically name function:
    const name = `or(${conditions.map(c => c.name || 'unknownCondition').join(',')}`;
    this._condition = { [name]: ({...options}) => testConditions.some(c => c(options)) }[name];
    return this;
  }

  public and(...conditions: ICondition[]): Scope {
    const prevCondition = this.condition;
    const testConditions = prevCondition === All ? conditions : [All, ...conditions];
    // dynamically name function:
    const name = `and(${conditions.map(c => c.name || 'unknownCondition').join(',')}`;
    this._condition = { [name]: ({...options}) => testConditions.every(c => c(options)) }[name];

    return this;
  }

  public get condition(): ICondition {
    return this._scope.condition;
  }

  private set _condition(value: ICondition) {
    this._scope.condition = value;
  }

  protected get _scope(): IScopeDef {
    return this._resource[this.actionName][this.scopeIndex];
  }
}
