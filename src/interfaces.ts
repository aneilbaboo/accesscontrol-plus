export type IContext = any; // tslint:disable-line
export type IConstraint = any; // tslint:disable-line
export type IConstraintGenerator = (context: IContext) => (Promise<any> | any); // tslint:disable-line
export type ICondition = (context: IContext) => boolean;
export type IScopeRequest = string;

export interface IMap<T> {
  [name: string]: T;
}

export interface IRoleDef {
  resources: IResourceDefs;
  inherits?: string[];
}
export type IResourceDef = IMap<IScopeDef[]>;
export type IRoleDefs = IMap<IRoleDef>;
export type IResourceDefs = IMap<IResourceDef>;

export type IExplanation = any; // tslint:disable-line
export type IExplanationGenerator = (permission: IPermission, context: IContext) => IExplanation;

export type IFieldDefs = IMap<boolean>;
export type IEffect = 'grant' | 'deny';
export type IFieldTest = (field: string | void, context?: IContext) => (Promise<boolean> | boolean);
export type IFieldGenerator = (ctx: IContext) => (Promise<IFieldDefs> | IFieldDefs);

export interface IPermission {
  granted: IScopeRequest | void;
  denied: IScopeRequest[] | void;
  constraint: IConstraint;
  fields: IFieldDefs;
  field(field: string): boolean;
}

export interface IScopeDef {
  condition: ICondition;
  constraint?: IConstraintGenerator | IConstraint;
  effect: IEffect;
  fieldGenerator?: IFieldGenerator;
  explanationGenerator?: IExplanationGenerator;
}
