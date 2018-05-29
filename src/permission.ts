/// <reference path="./interfaces.ts" />

import {
  IExplanation, IConstraint, IFieldDefs, IMap, IPermission, IScopeDef, IScopeRequest
} from './interfaces';

export class Permission implements IPermission {
  private _denied?: IScopeRequest[] | void;
  private _constraint?: IConstraint;
  private _fields?: IFieldDefs;
  private _granted?: IScopeRequest;

  public get granted(): IScopeRequest | void {
    return this._granted;
  }
  public get denied() { return this._denied; }
  public get constraint() { return this._constraint; }
  public get fields() { return this._fields || {}; }
  public field(field: string): boolean {
    if (this._granted && this._fields) {
      return Permission.testField(field, this._fields)[1];
    }
    return false;
  }

  public grant(scopeRequest: IScopeRequest, fields?: IFieldDefs, constraint?: IConstraint): void {
    if (this._granted) {
      throw new Error('Attempt to change permission grant');
    }
    this._granted = scopeRequest;
    this._fields = fields;
    this._constraint = constraint;
  }

  public deny(scopeRequest?: IScopeRequest, fields?: IFieldDefs): void {
    this._denied = this._denied ? this._denied : [];
    if (scopeRequest) {
      this._denied.push(scopeRequest);
    }
  }

  public static testField(field: string, fields: IFieldDefs): [string, boolean] {
    if (fields.hasOwnProperty(field)) {
      return [field, fields[field]];
    } else if (fields.hasOwnProperty('*')) {
      return ['*', fields['*']];
    } else {
      return ['', false];
    }
  }
}
