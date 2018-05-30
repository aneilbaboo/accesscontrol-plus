import { AccessControlPlus, IContext, Permission } from '.';

describe('Given the README.md example,', function () {

  function userIsResourceOwner({user, resource}: IContext) {
    return user.id === resource.ownerId;
  }
  function userImpersonatesResourceOwner({user, resource}: IContext) {
    return user.impersonationId === resource.ownerId;
  }
  function articleIsPublished({resource}: IContext) {
    return resource.state === 'published';
  }

  let ac: AccessControlPlus;

  beforeEach(function () {
    ac = new AccessControlPlus();
    ac
      .deny('public').scope('*:*')
      .grant('public')
        .scope('article:read')
          .where(articleIsPublished)
            .onFields('allowedPublicField', '!disallowedPublicField')
      .grant('author').inherits('public')
        .resource('article')
          .action('create').withConstraint(({user}) => ({ ownerId: user.id }))
          .action('read').where(userIsResourceOwner).onFields('*')
          .action('update').where(userIsResourceOwner).onFields('*')
      .grant('admin').inherits('author')
        .scope('article:read')
          .where(userImpersonatesResourceOwner)
        .scope('user:read')
          .onFields('*', '!superPrivateData')
      .grant('superadmin').inherits('admin')
        .scope('user:*');
  });

  const author = { id: 1234 }; // determined by request authentication

  const draft = { ownerId: 1234, state: 'draft' }; // retrieved from db
  const published = { ownerId: 1234, state: 'published', text: '...' }; // retrieved from db
  const adminUser = { id: 999, impersonationId: 1234 };
  const superAdmin = { id: 222 };

  it('should let the public read a published article', async function () {
    const permission = await ac.can('public', 'article:read', { user: null, resource: published });
    expect(permission.granted).toBeTruthy();
    expect(permission.denied).toBeUndefined();
  });

  it('should let the public read allowed fields on a published article', async function () {
    const permission = await ac.can('public', 'article:read:allowedPublicField', {
      user: null, resource: published
    });
    expect(permission.granted).toBeTruthy();
  });

  it('should let an author read their own unpublished article', async function () {
    const permission = await ac.can('author', 'article:read:allowedPublicField', {
      user: author, resource: draft
    });
    expect(permission.granted).toBeTruthy();
  });

  it('should not let the public read disallowed fields on a published article', async function () {
    const permission = await ac.can('public', 'article:read:disallowedPublicField', {
      user: null, resource: published
    });
    expect(permission.granted).toBeFalsy();
    expect(permission.denied).toEqual(['grant:public:article:read:0:disallowedPublicField:']);
  });

  it('should not let the public read fields which have not been implicitly or explicitly allowed', async function () {
    const permission = await ac.can('public', 'article:read:unmentionedField', {
      user: null, resource: published
    });
    expect(permission.granted).toBeFalsy();
    expect(permission.denied).toHaveLength(1);
    expect(permission.denied[0]).toMatch(/grant:public:article:read:\d::/);
  });

  it('should not let the public read an unpublished article', async function () {
    const permission = await ac.can('public', 'article:read', { user: null, resource: draft });
    expect(permission.granted).toBeFalsy();
    expect(permission.denied).toHaveLength(1);
    expect(permission.denied[0]).toMatch(/^grant:public:article:read:\d::articleIsPublished/);
  });

  it('should allow an admin to read all fields on the user except explicitly denied ones', async function () {
    const allowedScope = await ac.can('admin', 'user:read:id', {});
    expect(allowedScope.granted).toBeTruthy();

    const disallowedScope = await ac.can('admin', 'user:read:superPrivateData', {});
    expect(disallowedScope.granted).toBeFalsy();
  });

  it('should let an author read their own draft article', async function () {
    const permission = await ac.can('author', 'article:read', { user: author, resource: draft });
    expect(permission.granted).toBeTruthy();
  });

  it('should let a user update their own article', async function () {
    const permission = await ac.can('user', 'article:update', { user: author, resource: draft });
    expect(permission.granted);
  });

  it('should not allow an admin to update a users article, even when impersonating', async function () {
    const permission = await ac.can('admin', 'article:update', { user: adminUser, resource: draft});
    expect(permission.denied).toBeDefined();
    expect(permission.denied).toHaveLength(1);
    expect(permission.denied[0]).toMatch(/grant:author:article:update:\d::userIsResourceOwner/);
  });

  it('should allow an admin to read a draft article if they are impersonating the user', async function () {
    const permission = await ac.can('admin', 'article:read', { user: adminUser, resource: draft});
    expect(permission.granted).toBeTruthy();
  });

  it('should allow a superadmin to do anything to user resources', async function () {
    const permission = await ac.can('superadmin', 'user:delete', { user: superAdmin, resource: author });
    expect(permission.granted).toBeTruthy();
  });

  it('should generate a constraint from the context when the permission is granted', async function () {
    const permission = await ac.can('author', 'article:create', { user: author });
    expect(permission.granted).toBeTruthy();
    expect(permission.constraint).toBeDefined();
    expect(permission.constraint).toEqual({
      ownerId: author.id
    });
  });

  it('should not generate a constraint when the permission is not granted', async function () {
    const permission = await ac.can('public', 'article:create', { user: author });
    expect(permission.granted).toBeFalsy();
    expect(permission.constraint).not.toBeDefined();
  });

  it('should expose the `Permiss`ion class', function () {
    expect(new Permission()).toBeInstanceOf(Permission);
  });
});
