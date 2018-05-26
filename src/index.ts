export type Context = any; // tslint:disable-line
export type Constraint = any; // tslint:disable-line
export type ConstraintGenerator = (context: Context) => (Promise<any> | any); // tslint:disable-line
export type Condition = (context: Context) => boolean;
export function All() { return true; }

export interface IMap<T> {
  [name: string]: T;
}

export interface IRole {
  resources: IMap<IResource>;
  inherits?: string[];
}

export type Fields = IMap<boolean>;
export type Effect = 'grant' | 'deny';
export type FieldTest = (field: string | void, context?: Context) => (Promise<boolean> | boolean);
export type Explanation = any; // tslint:disable-line
export type ExplanationGenerator = (permission: Permission, context: Context) => Explanation;

export interface IScope {
  condition: Condition;
  constraint?: ConstraintGenerator | Constraint;
  effect: Effect;
  fieldGenerator?: FieldGenerator;
}

export type FieldGenerator = (ctx: Context) => (Promise<Fields> | Fields);

export type IRequest = string;
export type IDenial = { request: IRequest, explanation: any }; // tslint:disable-line

export class Permission {
  private _granted?: IRequest;
  private _denied?: IDenial[];
  private _constraint?: Constraint;
  private _fields?: Fields;

  public get granted(): IRequest | void { return this._granted; }
  public get denied() { return this._denied; }
  public get constraint() { return this._constraint; }
  public get fields() { return this._fields; }
  public field(field: string): boolean {
    if (this._granted && this._fields) {
      return Permission.testField(field, this._fields);
    }
    return false;
  }

  public grant(scopeRequest: string, fields?: Fields, constraint?: Constraint) {
    if (this._granted || !scopeRequest) {
      throw new Error('Attempt to change permission grant');
    }
    this._granted = scopeRequest;
    this._fields = fields;
    this._constraint = constraint;
  }

  public deny(scopeRequest?: string, explanation?: Explanation) {
    this._denied = this._denied ? this._denied : [];
    if (scopeRequest) {
      this._denied.push({ request: scopeRequest, explanation });
    }
  }

  public static testField(field: string, fields: Fields) {
    if (fields.hasOwnProperty(field)) {
      return fields[field];
    } else {
      return fields['*'];
    }
  }
}

export type IResource = IMap<IScope[]>;
export type IRoles = IMap<IRole>;

export class RBACPlus {
  constructor(public roles: IRoles = {}) {}

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
   * @param roleName
   * @param scope - the permission being sought ({resource}:{action})
   * @param context - Arbitrary object providing values resolved by the where Conditions
   */
  public async can(roleName: string, scope: string, context?: Context): Promise<Permission> {
    const [resourceName, actionName, field] = scope.split(':');
    let permission = new Permission();
    await this.canRole(roleName, resourceName, actionName, field, context, permission);
    return permission;
  }

  private async canRole(
    roleName: string,
    resourceName: string,
    actionName: string,
    field: string,
    context: Context,
    permission: Permission): Promise<boolean> {
      const role: IRole = this.roles[roleName] || this.roles['*'];
      if (!role) {
        return false;
      }

      const roleResource = role.resources[resourceName] || role.resources['*'];

      if (roleResource) {
        const scopes = roleResource[actionName] || roleResource['*'];
        let exit = false;
        if (scopes) {
          const scopeRequest = [roleName, resourceName, actionName, field || ''].join(':');
          const [granted, terminate] = await this.processScopes(scopes, field, context, scopeRequest, permission);
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
   * @param {string} scopeRequest
   * @param {Permission} permission
   * @returns {Array<boolean, boolean>} granted, terminate
   * @memberof RBACPlus
   */
  private async processScopes(
    scopes: IScope[], field: string | void, context: Context, partialscopeRequest: string, permission: Permission
  ): Promise<[boolean, boolean]> {
    let terminate = false;
    for (const scope of scopes) {
      const scopeRequest = `${partialscopeRequest}:${scope.condition.name}`;
      let fields = await this.generateFields(scope, context);
      let fieldTest = !field || Permission.testField(field, fields);
      let conditionTest = await this.testCondition(scope.condition, context);
      if (scope.effect === 'grant') {
        if (fieldTest && conditionTest) {
          const constraint = (scope.constraint instanceof Function ?
            await scope.constraint(context)
            : scope.constraint
          );
          permission.grant(scopeRequest, fields, constraint);
          return [true, true];
        } else { // failed to grant:
          permission.deny(scopeRequest);
          terminate = !!field && !fieldTest; // field present, but fieldTest failed
        }
      } else { // effect === 'deny'
        if (fieldTest && conditionTest) { // explicitly denied
          permission.deny(scopeRequest);
          terminate = true;
        } // else: do nothing if deny failed
      }
    }

    return [false, terminate];
  }

  private async generateFields(scope: IScope, context: Context): Promise<Fields> {
    if (scope.fieldGenerator) {
      return await scope.fieldGenerator(context);
    } else {
      return {};
    }
  }
}

export class Role extends RBACPlus {
  constructor(roles: IRoles, public readonly roleName: string, public readonly effect: Effect = 'grant') {
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

  protected get _role(): IRole {
    return this.roles[this.roleName];
  }
}

export class Resource extends Role {
  constructor(roles: IRoles, roleName: string, effect: Effect, public readonly resourceName: string) {
    super(roles, roleName);
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
    return this.action('update');
  }

  protected get _resource(): IResource {
    return this.roles[this.roleName].resources[this.resourceName];
  }
}

export class Scope extends Resource {
  constructor(
    roles: IRoles, roleName: string, effect: Effect, resourceName: string,
    public readonly actionName: string,
    public readonly scopeIndex: number) {
    super(roles, roleName, effect, resourceName);
  }

  public withConstraint(constraint: Constraint): Scope {
    this._scope.constraint = constraint;
    return this;
  }

  /**
   * Generate acceptable fields dynamically, based on the context
   * E.g.,
   * ```scope.onDynamicFields((ctx: Context) => {
   *   if (ctx.userHasFullAccess) {
   *     return { '*': true };
   *   } else {
   *     return { '*': true, 'privateData': false };
   *   }
   * });
   * ```
   *
   * @param {FieldGenerator} fieldGen
   * @returns {Scope}
   * @memberof Scope
   */
  public onDynamicFields(fieldGen: FieldGenerator): Scope {
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

    this._scope.fieldGenerator = (context: Context) => fieldMap;
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
    return this._resource[this.actionName][this.scopeIndex];
  }

  /**
   *
   *
   * @private
   * @param {IMap<boolean>} scopedFields
   * @returns {FieldTest} - fn returning true (field found) false (field negation found) void (field not requested)
   * @memberof Scope
   */
  private makeFieldTest(scopedFields: IMap<boolean>): FieldTest {
    return function (field: string | void): boolean {
      return this.fieldSatisfied(field, scopedFields);
    };
  }

  private fieldSatisified(field: string | void, scopedFields: IMap<boolean>): boolean {
    if (field) {
      if (scopedFields.hasOwnProperty(field)) {
        // explicit scope provided for this field:
        return scopedFields[field];
      } else {
        // default to '*' field or false
        return scopedFields['*'] || false;
      }
    } else {
      // no field requirement
      return true;
    }
  }
}
