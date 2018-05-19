# RBACPlus

Roles-based access control with inheritance and attribute tests.

```js
import RBACPlus from 'rbac-plus';

function userIsResourceOwner({user, resource}: Context) {
  return user.id === resource.ownerId;
}
function userImpersonatesResourceOwner({user, resource}: Context) {
  return user.impersonationId === resource.ownerId;
}
function articleIsPublished({resource}: Context) {
  return resource.state === 'published';
}

const rbac = new RBACPlus();
rbac
  .grant('public')
    .resource('article')
        .action('read')
          .where(articleIsPublished)
  .grant('author').inherits('public')
    .resource('article')
      .action('read').where(userIsResourceOwner)
      .action('update').where(userIsResourceOwner)
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

// let public read published articles
rbac.can('public', 'article:read', { user: null, resource: published }); // =>true

// don't allow public to read draft articles
rbac.can('public', 'article:read', { user: null, resource: draft }); // => false

// let an author read their own draft article
  expect(rbac.can('author', 'article:read', { user, resource: draft }); // => true
});

// allow a user to update their own article
rbac.can('user', 'article:update', { user: user, resource: draft }); // => true

// do not allow an admin to update a users article, even if they are impersonating them
rbac.can('admin', 'article:update', { user: adminUser, resource: draft}); // => false
    });

// allow an admin to read a draft article if they are impersonating the user
rbac.can('admin', 'article:read', { user: adminUser, resource: draft}); // => true

// allow a superadmin to do anything to user resources
rbac.can('superadmin', 'user:delete', { user: superAdmin, resource: user }); // => true
```

