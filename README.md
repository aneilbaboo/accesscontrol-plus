# RBACPlus

Role based access control with inheritance and attribute tests

```shell
npm install rbac-plus
```

## Features

* Roles with inheritance
* Globbing to match roles and scopes
* Attribute-based access control
* Resource constraints based on permission
* Informative grant/deny messages
* Chainable API useful for modular policy definition
* Typescript ready

## Quick start

1. Create RBACPlus instance
  ```js
  import {RBACPlus} from 'rbac-plus';

  const rbacPlus = new RBACPlus();
  ```

2. Define roles, scopes and conditions
  ```js
  rbacPlus
    .grant('user')
      .resource('posts')
        .action('read').onFields('*', '!dontreadthisfield')
        .action('create')
        .action('update').where(userIsAuthor)
    .grant('admin').inherits('user')
      .resource('users')
        .action('*');

  function userIsAuthor({user, post}) {
    return user.id == post.authorId;
  }
  ```

3. Test whether permission is granted
```js
  let permission;
  permission = accessControl.can('user', 'posts:update', { user: {id: 123}, post: {authorId: 123}}); // permission.granted => truthy
  permission = accessControl.can('user', 'posts:update', { user: {id: 999}, post: {authorId: 123}}); // permission.granted => falsy
  permission = accessControl.can('admin', 'users:create'); // permission.granted == true
  permission = accessControl.can('user', 'users:create'); // permission.granted == true
  ```

## API

### RBACPlus

Top level object which exposes the API.

#### constructor
```js
import {RBACPlus} from 'rbac-plus';
// normally use this:
const rbac = new RBACPlus();
```
or
```js
import {All} from 'rbac-plus'; // special condition which matches everything
const rbac = new RBACPlus({
  admin: {
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

#### #can
Returns a permission indicating whether the given role can access the scope:
```js
// context is a developer-defined value passed to conditions
// (see Scope #where, #and, #or)
const context = { user: { id: 'the-user-id' } };
rbac.can('admin', 'delete:user', context);
```

#### #grant
Returns a Role object which will grant permissions
```js
rbac.grant('admin') // => Role instance
```

#### #deny
Returns a Role object which will grant permissions
```js
rbac.deny('admin') // => Role instance
```

#### #roles

### Role
Represents a named role.

#### #inherits
Inherit permissions from another role:
```js
role.inherits('public'); // => Role instance
```

#### #resource
Access a resource of a particular role:
```js
role.resource('article'); // => Resource instance
```

#### #scope
Access a scope, a short cut for accessing a resource then accessing an action:
```js
role.scope('article:read'); // same as role.resource('article').action('read')
```

### Resource
A resource object is obtained using the `Role.resource` method

#### #action
```js
resource.action('read'); // => Scope
```

### Scope
Represents a specific permission, and enables setting conditions and constrains on the permission.

#### #where
Sets one or more tests which must all pass for the permission to be granted. This method is equivalent to `scope.and`, except for the name generated in the `permission.grant` and `permission.deny`:

```js
function async ownsResource({ user, request }) {
  const resource = await MyResource.loadFromDB({ id: request.params.id });
  return resource.id === user.id;
}
scope.where(ownsResource); // => Scope
```

#### #and
Grants permission for the scope if all of the tests return truthy values:
```js
scope.and(test1, test2, test3...);
```

#### #or
Grants permission for the scope if any of the tests return a truthy value:
```js
scope.or(test1, test2, test3...);
```

#### #withConstraint
Add a function which returns a constraint useful to the developer for passing to a function that accesses a resource:
```js
rbac.grant('user').scope('article:create')
  .withConstraint(({user})=>({ ownerId: user.id})); // => Scope
...
let permission = await rbac.can('user', 'article:create', { user: { id: 123 }});
if (permission.granted) {
  await Article.create(permission.constraint); // { ownerId: 123 }
}
```

#### #onFields
Restrict the grant/denial to specific fields. Provide a list of fieldNames. Use `*` for all fields, `!{fieldName}` to exclude a field:

```js
// grant on all fields
rbac.grant('admin').scope('user:read')
  .onFields('*');
rbac.can('admin', 'user:read:superPrivateData'); // permission.granted => yes
```

```js
// deny on specific fields
rbac.grant('admin').scope('user:read')
  .onFields('*', '!privateData');
rbac.can('admin', 'user:read:privateData'); // permission.granted => no
rbac.can('admin', 'user:read:name'); // permission.granted => yes
```
```js
// grant on specific fields
rbac.grant('admin').scope('user:read')
  .onFields('name');
rbac.can('admin', 'user:read:name'); // permission.granted => yes
rbac.can('admin', 'user:read:phoneNumber'); // permission.granted => no
```

#### onDynamicFields
Generate field grants dynamically, given a context. You can use async calls, if needed:
```js
rbac.grant('admin').scope('user:read')
  .onDynamicFields(async ({admin, user}: Context) => {
    const permissive = await myBackend.adminHasPermissionFromUser(admin, user);
    if (permissive) {
      return { '*': true };
    } else {
      return { 'id': true, 'userName': true, 'phoneNumber': true };
    }
  });
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
  permission = await rbac.can('public', 'article:read', { user: null, resource: published });
  // permission.granted => truthy

  // public can't read draft articles
  permission = await rbac.can('public', 'article:read', { user: null, resource: draft });
  // permission.granted => falsy
  // permission.denied = ['public:article:read:articleIsPublished']

  // author can read their own draft article
  permission = rbac.can('author', 'article:read', { user, resource: draft });
  // permission.granted => truthy

  // auth can update their own article
  permission = rbac.can('user', 'article:update', { user: user, resource: draft });
  // permission.granted => truthy

  // admin cannot update an author's article, even if they are impersonating them
  permission = rbac.can('admin', 'article:update', { user: adminUser, resource: draft});
  // permission.granted => falsy
  // permision.denied = [ 'author:article:update:userIsResourceOwner' ]

  // admin can read a draft article if they are impersonating the author
  permission = rbac.can('admin', 'article:read', { user: adminUser, resource: draft});
  // permission.granted => truthy

  // superadmin can do anything to user resources
  permission = rbac.can('superadmin', 'user:delete', { user: superAdmin, resource: user });
  // permission.granted => truthy
}
```
