/// <amd-module name="rbac-plus/permission" />

import { IRequest, IDenial, IExplanation, IConstraint, IFieldDefs, IMap, IPermission } from './interfaces';

export class Permission implements IPermission {
  private _granted?: IRequest;
  private _denied?: IDenial[];
  private _constraint?: IConstraint;
  private _fields?: IFieldDefs;

  public get granted(): IRequest | void { return this._granted; }
  public get denied() { return this._denied; }
  public get constraint() { return this._constraint; }
  public get fields() { return this._fields || {}; }
  public field(field: string): boolean {
    if (this._granted && this._fields) {
      return Permission.testField(field, this._fields);
    }
    return false;
  }

  public grant(scopeRequest: string, fields?: IFieldDefs, constraint?: IConstraint): void {
    if (this._granted || !scopeRequest) {
      throw new Error('Attempt to change permission grant');
    }
    this._granted = scopeRequest;
    this._fields = fields;
    this._constraint = constraint;
  }

  public deny(scopeRequest?: string, explanation?: IExplanation): void {
    this._denied = this._denied ? this._denied : [];
    if (scopeRequest) {
      this._denied.push({ request: scopeRequest, explanation });
    }
  }

  public static testField(field: string, fields: IFieldDefs) {
    if (fields.hasOwnProperty(field)) {
      return fields[field];
    } else {
      return fields['*'];
    }
  }
}
