# RBACPlus

Roles-based access control with inheritance and attribute tests.

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
// 4 roles: public, author, admin, superadmin
//
rbac
  .deny('public') // by default, the public cannot use any resource
    .scope('*:*')
  .grant('public')
    .scope('article:read').where(articleIsPublished)
  .grant('author').inherits('public')
    .resource('article')
      .action('read') // === .scope('article:read')
        .where(userIsResourceOwner)
      .action('update') // === .scope('article:update')
        .where(userIsResourceOwner)
  .grant('admin').inherits('author')
    .resource('article')
      .action('read').where(userImpersonatesResourceOwner)
  .grant('superadmin').inherits('admin')
    .resource('user')
      .action('*');

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

