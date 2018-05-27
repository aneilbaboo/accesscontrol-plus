[![CircleCI](https://circleci.com/gh/aneilbaboo/rbac-plus/tree/master.svg?style=shield&circle-token=dd1dce6e44faad80e9205bd87f081ae5f0d21428)](https://circleci.com/gh/aneilbaboo/rbac-plus/tree/master) [![codecov](https://codecov.io/gh/aneilbaboo/rbac-plus/branch/master/graph/badge.svg)](https://codecov.io/gh/aneilbaboo/rbac-plus) [![Maintainability](https://api.codeclimate.com/v1/badges/701ac0ef9089cee1a13a/maintainability)](https://codeclimate.com/github/aneilbaboo/rbac-plus/maintainability)

# RBACPlus

Role based access control with inheritance and attribute tests

```shell
npm install rbac-plus
```

## Features

* Write policies that are easy to read
* Define roles using inheritance
* Write fine grained permissions
* Test arbitrary attributes (e.g. of the request or requested resource)
* Restrict permissions to fields on the resource
* Apply constraints to operations on the resource
* Get explanation why a permission was granted or denied
* Use wildcard matching in policies
* Define policies in parts
* Use Typescript

## Quick start

```js
//
// Create RBACPlus instance to manage a group of roles
//
import {RBACPlus} from 'rbac-plus';

const rbacPlus = new RBACPlus();

//
// Define roles, scopes and conditions
//
rbacPlus
  .deny('public').resource('*').action('*')
  .grant('user')
    .resource('posts')
      .create
      .read.onFields('*', '!dontreadthisfield') // allow read on all fields but one
      .update.where(userIsAuthor)
      .delete.where(userIsAuthor)
  .grant('admin').inherits('user')
    .resource('users')
      .action('*');

function userIsAuthor({user, post}) {
  return user.id == post.authorId;
}

//
// Test whether permission is granted
//
let permission;

permission = await rbacPlus.can('user', 'posts:create');
// permission.granted => truthy

permission = await rbacPlus.can('user', 'users:create');
// permission.granted => falsy

permission = await rbacPlus.can('admin', 'users:create');
// permission.granted => truthy (because of inheritance)

// using context:
permission = await rbacPlus.can(
  'user',                                   // role
  'posts:update',                           // scope
  { user: {id: 123}, post: {authorId: 123}} // context
); // permission.granted => truthy
```

## Concepts

### Role Based Access Control (RBAC) versus Attribute Based Access Control (ABAC)

Role based authorization defines permissions in terms of roles in an organization - users, editors, authors, etc.  This is convenient, but RBAC relies on static definitions and can't use contextual information (time, location, dynamic group membership, etc) to determine access rights.  In traditional RBAC, contextual tests must be performed in other layers of an application. On the other hand, ABAC allows use of contextual information, but is also more complicated, and is [sometimes described as overkill](https://objectpartners.com/2017/06/16/abac-or-rbac/ ) for solving typical problems. For more discussion, see: https://iamfortress.net/2017/02/15/rbac-vs-abac/.

### RBACPlus: RBAC with ABAC-powers

This library combines useful properties of RBAC and ABAC. You define roles and permissions, making it easy to define and manage your policies, like tradition RBAC, but also implement fine-grained context-sensitive tests, like ABAC.

The `RBACPlus` class provides the top-level API of this library. Use it to define role permissions (using `grant` or `deny`), add conditions using `where`, `and` and `or`, and test whether a permission (using `can`). (See [API](#API)).

```typescript
const rbac = new RBACPlus();
rbacPlus.deny('public').scope('*:*');
rbacPlus.grant('author').scope('post:update')
  .where(authorIsResourceOwner); // a function you write which tests attributes
```
### Effect: Grant or Deny
A grant permits a user

### Definitions

#### Roles, Resources, Actions and Inheritance

Each `role` (e.g., "admin" or "user") has `scopes` which **grant** or **deny** permission to perform `actions` on `resources`, potentially limited to certain `fields` of the resource.  Roles can [inherit](##inherits) scopes from other roles.

#### Scopes

A `scope` name is a `resource:action` pair or a `resource:action:field` triplet. For example,

```js
"post:read" // read a post resource
"post:read:text" // read the text field of a post resource
```

##### Shortcuts for creating scopes
```js
const userRole = rbacPlus.grant('user');

// the following are all equivalent:
userRole.scope('post:create')
userRole.resource('post').action('create')
userRole.resource('post').create // see CRUD shortcuts
```

#### Permissions
A `permission` is an instance of the `Permission` class returned by `RBACPlus#can`:
```typescript
const permission: Permission = await rbacPlus.can('user', 'post:read');

// If the permission is granted
permission.granted === "user:post:read" // or similar

// if permission is denied:
permission.denied === [ { request: "..." }, { request: "..." } ] // request represent the scopes that were denied
```
If [constraints](##withConstraint) were defined for the scope, the permission will contain a `constraint` key.


#### Conditions

Scopes can be restricted with `conditions`, javascript sync or async functions of the form:

```typescript
type Condition = (ctx: Context)=> Promise<boolean> | boolean // type Context = any
```

Conditions should be *named* functions. The condition name is used to generate a description string, assigned to `permission.grant`

```js
// Add a condition to post:update:
rbacPlus.grant('user').scope('post:update')
  .where(userIsOwner); // add a condition

function userIsOwner({user, resource}) {
  return user.id === resource.ownerId;
}

permission = await rbacPlus.can('user', 'post:update',
  { user:     { id:      1 },
    resource: { ownerId: 1 }});

permission.granted // => 'user:post:update::userIsOwner'
```

If a condition throws an error, it is treated as though it returned `false`. (Note: this may cause unexpected behavior if a condition is used to `deny`, so this behavior may change in the future, such that exceptions will be treated as `true` for `deny`).

#### Context

The `context` is a developer-specified value that is passed to the test function `can`, which in turn passes the value to various developer-defined functions involved in testing scopes. Arbitrary values such as the current user, the request parameters, time, environment and location can be passed in the context. See the example above under [Conditions](#Conditions).

```typescript
type Context = any;
```

#### Fields
Fields represent attributes of the resource. They can be allowed or denied using the [`onFields`](#onfields) method.

```typescript
// E.g., Allow fields and disallow specific fields:
rbacPlus.grant('user').resource('post').read.onFields('*', '!stats');

// request permission for action on a specific field:
rbac.can('user', 'post:read:stats'); // permission denied
rbac.can('user', 'post:read:foo'); // permission granted
permission = rbac.can('user', 'post:read');
// permission granted with
// permission.fields = { "*": true, "stats": false }

```

Alternatively, you can request a permission for the action, and you will receive a permission with a `fields` property which is an object describing which fields are accessible:
```
rbac.

Field permissions can also be calculated dynamically be providing a function (which can be async). The function returns an Object mapping field names to boolean values indicating whether the field is granted or not.
E.g., the following is equivalent to the `onFields` call shown above.
```typescript
rbacPlus.grant('user').resource('post').read.onDynamicFields((ctx: Context) => ({
  '*': true, // grant all fields
  stats: false
}));
```


## API

### RBACPlus

Top level object which exposes the API.

#### constructor
```js
import {RBACPlus} from 'rbac-plus';
const rbacPlus = new RBACPlus();
```

#### grant

Returns a Role object which can be used to grant permissions
```js
// rbacPlus.grant(roleName)
rbacPlus.grant('admin') // => Role instance
```

#### deny
Returns a Role object which can be used to deny permissions
```js
// rbacPlus.deny(roleName);
rbacPlus.deny('admin') // => Role instance
```

#### can

Async function returning a permission indicating whether the given role can access the scope:
```js
// context is a developer-defined value passed to conditions
// (see Scope #where, #and, #or)
const context = { user: { id: 'the-user-id' } };
// rbacPlus.can(role, scope, context)
await rbacPlus.can('admin', 'delete:user', context);
```

The first argument can also be a list of role names.

#### advanced constructor
The constructor can also be passed a Javascript object which defines the policies directly. This is the underlying structure that the RBACPlus methods operate on:
```js
import {RBACPlus, All} from 'rbac-plus';
const rbac = new RBACPlus({ // this is the underlying structure the API builds
  admin: {                  // and uses to determine permissions
    resources: {
      user: {
        delete: {
          condition: All,
          effect: 'grant'
        }
      }
    }
    inherits: [ 'user' ]
  }
});

```


### Role
Represents a named role.

#### inherits
Inherit scopes from another role:
```js
// role.inherits(roleName)
role.inherits('public'); // => Role instance
```

#### resource
Access a resource of a particular role:
```js
// role.resource(resourceName)
role.resource('article'); // => Resource instance
```

#### scope
Access a scope, a short cut for accessing a resource then accessing an action:
```js
// role.scope(scopeName)
role.scope('article:read'); // same as role.resource('article').action('read')
```

### Resource
A resource object is obtained using the `Role.resource` method

#### action
```js
// resource.action(actionName)
resource.action('read'); // => Scope
```
Note: you can create multiple scopes per action. This allows you to provide different constraints and fields for the same action:
```js
resource
  .action('read').where(foobar)
    .withConstraint(FooBarConstraint).onFields('foo', 'bar')
  .action('read').where(baz)
    .withConstraint(BazConstraint).onFields('baz');
```

#### CRUD shortcuts

```js
resource.create // = resource.action('create');
resource.read   // = resource.action('read');
resource.update // = resource.action('update');
resource.delete // = resource.action('delete');
```

### Scope
Represents a specific permission, and enables setting conditions and constrains on the permission.

#### where
Sets one or more tests which must all pass for the permission to be granted. This method is equivalent to `scope.and`, except for the name generated in the `permission.grant` and `permission.deny`:

```js
// scope.where((context: Context) => boolean)
// scope.where(async (context: Context) => Promise<boolean>)
function async ownsResource({ user, request }) {
  const resource = await MyResource.loadFromDB({ id: request.params.id });
  return resource.id === user.id;
}
scope.where(ownsResource); // => Scope
```

#### and
Grants permission for the scope if all of the tests return truthy values:
```js
scope.and(test1, test2, test3...); // => Scope
```

#### or
Grants permission for the scope if any of the tests return a truthy value:
```js
scope.or(test1, test2, test3...); // => Scope
```

#### withConstraint
Note: constraints are deprecated and may be removed from a future version of the API.

Add a function which returns a constraint useful to the developer for passing to a function that accesses a resource:
```js
rbacPlus.grant('user').scope('article:create')
  .withConstraint(({user})=>({ ownerId: user.id})); // => Scope
...
let permission = await rbacPlus.can('user', 'article:create', { user: { id: 123 }});
if (permission.granted) {
  await Article.create(permission.constraint); // { ownerId: 123 }
}
```

#### onFields
Restrict the grant/denial to specific fields. Provide a list of fieldNames. Use `*` for all fields, `!{fieldName}` to exclude a field:

```js
// grant on all fields
rbacPlus.grant('admin').scope('user:read')
  .onFields('*');
rbacPlus.can('admin', 'user:read:superPrivateData'); // permission.granted => yes
```

```js
// deny on specific fields
rbacPlus.grant('admin').scope('user:read')
  .onFields('*', '!privateData');
await rbacPlus.can('admin', 'user:read:privateData'); // permission.granted => no
await rbacPlus.can('admin', 'user:read:name'); // permission.granted => yes
```
```js
// grant on specific fields
rbacPlus.grant('admin').scope('user:read')
  .onFields('name');
await rbacPlus.can('admin', 'user:read:name'); // permission.granted => yes
await rbacPlus.can('admin', 'user:read:phoneNumber'); // permission.granted => no
```

#### onDynamicFields
Generate field grants dynamically, given a context. You can use async calls, if needed:
```js
rbacPlus.grant('admin').scope('user:read')
  .onDynamicFields(async ({admin, user}: Context) => {
    const permissive = await myBackend.adminHasPermissionFromUser(admin, user);
    if (permissive) {
      return { '*': true };
    } else {
      return { 'id': true, 'userName': true, 'phoneNumber': true };
    }
  });
```

### Permission
Object returned by `RBACPlus#can`

#### granted
If permission granted this will be a string describing the scope granted.

#### denied
If permission denied, this is set to an array of objects that contain

#### field
Tests whether permission was granted for the specified field. Accounts for wildcards and denied fields (`!foo`) provided in [`.onFields`](#onFields).

```js
permission.field('foo') // => true or false
```

## Extended Example

```js
import RBACPlus from 'rbac-plus';

function userIsResourceOwner({user, resource}) {
  return user.id === resource.ownerId;
}
function userImpersonatesResourceOwner({user, resource}) {
  return user.impersonationId === resource.ownerId;
}
function articleIsPublished({resource}) {
  return resource.state === 'published';
}

const rbac = new RBACPlus();
//
// 4 roles in this scenario: public, author, admin, superadmin
//
rbac
  // Define roles:
  //
  // PUBLIC
  //
  .deny('public') // start by disallowing the public access to everything
    .scope('*:*')
  .grant('public')
    .scope('article:read')
      .where(articleIsPublished)
        .onFields('*', '!viewers') // allow all fields except viewers
  //
  // AUTHOR
  //
  .grant('author').inherits('public')
    .resource('article')
      .action('create')
        // add a constraint - to include when creating the article:
        .withConstraint(({user})=>({ ownerId: user.id }))
      .action('read') // === .scope('article:read')
        .where(userIsResourceOwner)
      .action('update') // === .scope('article:update')
        .where(userIsResourceOwner)
  //
  // ADMIN
  //
  .grant('admin').inherits('author')
    .resource('article')
      .action('read').where(userImpersonatesResourceOwner)
  //
  // SUPERADMIN
  //
  .grant('superadmin').inherits('admin')
    .resource('user')
      .action('*');

//
// The following are objects which are generated by your code
// during a request - users, resources, etc:
//
const user = { id: 1234 }; // determined by request authentication
const draft = { ownerId: 1234, state: 'draft', text: '...' }; // retrieved from db
const published = { ownerId: 1234, state: 'published', text: '...' }; // retrieved from db
const adminUser = { id: 999, impersonationId: 1234 };
const superAdmin = { id: 222 };

async function testPermissions {
  let permission;
  // public can read published articles
  permission = await rbacPlus.can('public', 'article:read', { user: null, resource: published });
  // permission.granted => truthy

  // public can't read draft articles
  permission = await rbacPlus.can('public', 'article:read', { user: null, resource: draft });
  // permission.granted => falsy
  // permission.denied = ['public:article:read:articleIsPublished']

  // author can read their own draft article
  permission = rbacPlus.can('author', 'article:read', { user, resource: draft });
  // permission.granted => truthy

  // auth can update their own article
  permission = rbacPlus.can('user', 'article:update', { user: user, resource: draft });
  // permission.granted => truthy

  // admin cannot update an author's article, even if they are impersonating them
  permission = rbacPlus.can('admin', 'article:update', { user: adminUser, resource: draft});
  // permission.granted => falsy
  // permision.denied = [ 'author:article:update:userIsResourceOwner' ]

  // admin can read a draft article if they are impersonating the author
  permission = rbacPlus.can('admin', 'article:read', { user: adminUser, resource: draft});
  // permission.granted => truthy

  // superadmin can do anything to user resources
  permission = rbacPlus.can('superadmin', 'user:delete', { user: superAdmin, resource: user });
  // permission.granted => truthy
}
```
