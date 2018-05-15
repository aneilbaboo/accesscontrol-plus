# RBACPlus

Roles-based access control with inheritance and attribute tests.

```js
import RBACPlus from 'rbac-plus';

function userIsResourceOwner({user, resource}) {
  return user.get('id') === resource.get('ownerId');
}
function userImpersonatesResourceOwner({context, resource}) {
  return context.impersonationId === resource.get('ownerId');
}
function reportPublished({resource}) { return resource.get('state')==='published'); }

const rbac = new RBACPlus();
rbac
  .grant('public')
    .resource('Post')
       .action('read')
         .where(reportPublished)
  .grant('user')
    .resource('Post')
      .action('update')
        .where(userIsResourceOwner)
      .inherits('public')
  .grant('admin').inherits('user')

const user = { id: 'auth0|1234' }; // determined by request authentication
const post = { ownerId: 'auth0|1234', text: '...', ... }; // retrieved from db
const context = { user: user, resource: post };
rbac.can('user', 'Report:create', context); // => true
rbac.can('admin', 'Report:create', context); // => true
rbac.can('public', 'Report:create', context); // => false
rbac.can('admin', 'Report:read', context); // => true
```

