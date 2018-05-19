import {RBACPlus, Role, Resource, Scope, Context, All} from './';

describe('RBACPlus', async function () {
  describe('#grant', async function () {
    it('should generate a valid role', async function () {
      const rbac = new RBACPlus();
      expect(rbac.grant('user')).toBeInstanceOf(Role);
      expect(rbac.roles).toEqual({
        user: { resources: {}}
      });
    });

    it('should add new roles by chaining', async function () {
      const rbac = new RBACPlus();
      expect(rbac.grant('user').grant('admin')).toBeInstanceOf(Role);
      expect(rbac.roles).toEqual({
        user: { resources: {}},
        admin: { resources: {}}
      });
    });

    describe('Role', async function () {

      describe('#inherit', async function () {
        it('should allow inheritance', async function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post').grant('admin').inherits('user')).toBeInstanceOf(Role);
          expect(rbac.roles).toEqual({
            user: { resources: { Post: {} }},
            admin: { inherits: ['user'], resources: {} }
          });
        });
      });

      describe('#scope', function () {
        it('should return a Scope', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').scope('Post:read')).toBeInstanceOf(Scope);
          expect(rbac.roles).toEqual({
            user: { resources: { Post: { read: {
              condition: All,
              constraints: {},
              effect: 'grant'
            } } }}
          });
        });
      });

      describe('#resource', function () {
        it('should return a Resource', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post')).toBeInstanceOf(Resource);
          expect(rbac.roles).toEqual({
            user: { resources: { Post: {} }}
          });
        });

        it('should add new resources by chaining', async function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post').resource('Comment')).toBeInstanceOf(Resource);
          expect(rbac.roles).toEqual({
            user: { resources: {
              Post: {},
              Comment: {}
            }}
          });
        });

        describe('#action', async function () {
          it('should return a scope', async function () {
            const rbac = new RBACPlus();
            expect(rbac.grant('user').resource('Post').action('read')).toBeInstanceOf(Scope);
          });
        });

      });
    });
  });
  describe('can', async function () {
    describe('role with where scope', async function () {
      const userOwnsResource = ({resource, user}) => resource.ownerId === user.id;
      const rbac = new RBACPlus();
      rbac.grant('user')
        .resource('Post')
          .action('create')
            .where(userOwnsResource);

      it('should return true when the permission is requested and the test is satisfied', async function () {
        const permission = await rbac.can('user', 'Post:create', {
          resource: { ownerId: 123},
          user: { id: 123 }
        });
        expect(permission.granted).toBeTruthy();
      });

      it('should return false when the permission is requested but the request is not satisified', async function () {
        const permission = await rbac.can('user', 'Post:create', {
          resource: { ownerId: 999},
          user: { id: 123 }
        });
        expect(permission.granted).toBeFalsy();
      });
    });

    it('should return true for a role which inherits from the role with the permission', async function () {
      const rbac = new RBACPlus();
      rbac.grant('user')
        .resource('Post')
          .action('create')
            .where(({resource, user}) => resource.ownerId === user.id)
        .grant('admin').inherits('user');
      const permission = await rbac.can('admin', 'Post:create', {});
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toBeTruthy();
      expect(permission.denied).toHaveLength(1);
    });

  });

  describe('Given the README.md example,', async function () {

    function userIsResourceOwner({user, resource}: Context) {
      return user.id === resource.ownerId;
    }
    function userImpersonatesResourceOwner({user, resource}: Context) {
      return user.impersonationId === resource.ownerId;
    }
    function articleIsPublished({resource}: Context) {
      return resource.state === 'published';
    }

    let rbac = new RBACPlus();

    beforeEach(function () {
      rbac
        .deny('public').scope('*:*')
        .grant('public')
          .scope('article:read')
            .where(articleIsPublished)
        .grant('author').inherits('public')
          .resource('article')
            .action('read').where(userIsResourceOwner)
            .action('update').where(userIsResourceOwner)
        .grant('admin').inherits('author')
          .scope('article:read')
            .where(userImpersonatesResourceOwner)
        .grant('superadmin').inherits('admin')
          .scope('user:*');
    });

    const author = { id: 1234 }; // determined by request authentication

    const draft = { ownerId: 1234, state: 'draft', text: '...' }; // retrieved from db
    const published = { ownerId: 1234, state: 'published', text: '...' }; // retrieved from db
    const adminUser = { id: 999, impersonationId: 1234 };
    const superAdmin = { id: 222 };

    it('should let the public read a published article', async function () {
      const permission = await rbac.can('public', 'article:read', { user: null, resource: published });
      expect(permission.granted).toBeTruthy();
    });

    it('should not let the public read an unpublished article', async function () {
      const permission = await rbac.can('public', 'article:read', { user: null, resource: draft });
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toHaveLength(1);
      expect(permission.denied[0]).toEqual('public:article:read:articleIsPublished');
    });

    it('should let an author read their own draft article', async function () {
      const permission = await rbac.can('author', 'article:read', { user: author, resource: draft });
      expect(permission.granted).toBeTruthy();
    });

    it('should let a user update their own article', async function () {
      const permission = await rbac.can('user', 'article:update', { user: author, resource: draft });
      expect(permission.granted);
    });

    it('should not allow an admin to update a users article, even if they are impersonating them', async function () {
      const permission = await rbac.can('admin', 'article:update', { user: adminUser, resource: draft});
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toHaveLength(1);
      expect(permission.denied).toEqual([
        'author:article:update:userIsResourceOwner'
      ]);
    });

    it('should allow an admin to read a draft article if they are impersonating the user', async function () {
      const permission = await rbac.can('admin', 'article:read', { user: adminUser, resource: draft});
      expect(permission.granted).toBeTruthy();
    });

    it('should allow a superadmin to do anything to user resources', async function () {
      const permission = await rbac.can('superadmin', 'user:delete', { user: superAdmin, resource: author });
      expect(permission.granted).toBeTruthy();
    });
  });
});
